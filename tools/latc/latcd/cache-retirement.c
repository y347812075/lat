#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "cache-retirement.h"
#include "cache-capacity.h"
#include "../aot-v2/runtime/cache-domain.h"
#include "../aot-v2/runtime/cache-lifecycle.h"
#include "parson/parson.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

#define MANIFEST_LIMIT 4096
#define RECORD_LIMIT 65536
#define PREPARED_COMPLETION_HEADROOM 512
#define RETIREMENT_BUSY_MIN_US UINT64_C(60000000)
#define RETIREMENT_BUSY_MAX_US UINT64_C(3600000000)
#define RETIREMENT_SCHEDULE_LIMIT 4096
#define RETIREMENT_SCHEDULE_BYTES (4 * 1024 * 1024)
#define RETIREMENT_SCHEDULE_RECORD_BYTES 1024

static bool object_name_valid(const char *source, const char *name)
{
    if (!name || strncmp(source, name, 64)) return false;
    const char *suffix = name + 64;
    if (*suffix == '-') {
        suffix++;
        if (strlen(suffix) < 64 || strspn(suffix, "0123456789abcdef") != 64) return false;
        suffix += 64;
    }
    return !strcmp(suffix, ".so") || !strcmp(suffix, ".native") ||
           !strcmp(suffix, ".tbset");
}

static bool page_object_name_valid(const char *name)
{
    return name && strlen(name) >= 64 &&
        strspn(name, "0123456789abcdef") == 64 && object_name_valid(name, name);
}

static bool object_stat_equal(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
        a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_blocks == b->st_blocks &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

typedef struct RecoveryObject {
    struct stat identity;
    char *evidence;
} RecoveryObject;

struct LatcdRecoveryCursor {
    char *root_path;
    int root;
    DIR *directory;
    bool tombstones, done, failed, yielded;
    char *pending;
    struct stat pending_identity;
    GHashTable *verified;
    int hash_fd;
    char *hash_name;
    struct stat hash_identity;
    GChecksum *hash;
    uint64_t offset, bytes_left;
    int64_t deadline;
    LatcdRecoveryProgress progress;
};

static char *recovery_capture(int root, const char *source, const char *name,
                              LatcdRecoveryCursor *cursor);

static char *capture_objects(int directory, const char *source,
                             const char *const *names, size_t count)
{
    if (!source || strlen(source) != 64 ||
        strspn(source, "0123456789abcdef") != 64 || !names || !count || count > 6) return NULL;
    GKeyFile *objects = g_key_file_new();
    bool valid = true;
    g_key_file_set_integer(objects, "objects", "count", count);
    for (size_t i = 0; valid && i < count; i++) {
        if (!object_name_valid(source, names[i])) { valid = false; break; }
        int fd = openat(directory, names[i], O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        struct stat before, after, path;
        valid = fd >= 0 && !flock(fd, LOCK_SH | LOCK_NB) && !fstat(fd, &before) &&
            S_ISREG(before.st_mode) && before.st_uid == geteuid() &&
            before.st_nlink == 1 && !(before.st_mode & 0222) && before.st_size > 0;
        GChecksum *hash = g_checksum_new(G_CHECKSUM_SHA256);
        unsigned char buffer[65536];
        uint64_t total = 0;
        while (valid) {
            ssize_t bytes = read(fd, buffer, sizeof(buffer));
            if (bytes < 0 && errno == EINTR) continue;
            if (bytes < 0) { valid = false; break; }
            if (!bytes) break;
            total += bytes;
            if (total > (uint64_t)before.st_size) { valid = false; break; }
            g_checksum_update(hash, buffer, bytes);
        }
        valid = valid && total == (uint64_t)before.st_size && !fstat(fd, &after) &&
            !fstatat(directory, names[i], &path, AT_SYMLINK_NOFOLLOW) &&
            object_stat_equal(&before, &after) && object_stat_equal(&before, &path);
        if (valid) {
            char group[32];
            snprintf(group, sizeof(group), "object%zu", i);
            g_key_file_set_string(objects, group, "name", names[i]);
            g_key_file_set_uint64(objects, group, "device", before.st_dev);
            g_key_file_set_uint64(objects, group, "inode", before.st_ino);
            g_key_file_set_uint64(objects, group, "size", before.st_size);
            g_key_file_set_uint64(objects, group, "allocated", (uint64_t)before.st_blocks * 512);
            g_key_file_set_string(objects, group, "sha256", g_checksum_get_string(hash));
        }
        g_checksum_free(hash);
        if (fd >= 0) close(fd);
    }
    char *data = valid ? g_key_file_to_data(objects, NULL, NULL) : NULL;
    g_key_file_unref(objects);
    return data;
}

char *latcd_retirement_capture_objects(const char *root, const char *source,
                                      const char *const *names, size_t count)
{
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) return NULL;
    char *data = capture_objects(directory, source, names, count);
    close(directory);
    return data;
}

static int fail(char *error, size_t size, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if (error && size) vsnprintf(error, size, format, args);
    va_end(args);
    return -1;
}

static bool source_valid(const char *source)
{
    return source && strlen(source) == 64 &&
        strspn(source, "0123456789abcdef") == 64;
}

static int open_directory(int parent, const char *name, bool create)
{
    int fd = create ? latcd_cache_capacity_open_metadata_directory(parent, name) :
        openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd >= 0 && (fstat(fd, &st) || st.st_uid != geteuid() ||
                    (st.st_mode & 0077))) {
        close(fd);
        errno = EACCES;
        return -1;
    }
    if (fd >= 0 && create && fsync(parent)) {
        close(fd);
        return -1;
    }
    return fd;
}

static int open_store(int root, bool create)
{
    int gc = open_directory(root, ".gc", create);
    if (gc < 0) return -1;
    int records = open_directory(gc, "transactions", create);
    close(gc);
    return records;
}

static int roots_lock_gc(int gc, int operation, char *error, size_t error_size)
{
    if (operation != LOCK_SH && operation != (LOCK_SH | LOCK_NB) &&
        operation != (LOCK_EX | LOCK_NB))
        return fail(error, error_size, "invalid reference roots latch operation");
    int fd = gc < 0 ? -1 : latcd_cache_capacity_open_metadata_lock(gc, "reference-roots.lock");
    struct stat st, path;
    bool valid = fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) &&
        st.st_uid == geteuid() && st.st_nlink == 1 && !(st.st_mode & 0077) &&
        !st.st_size &&
        !lat_aot_v2_cache_lock_fd(fd, operation, error, error_size) &&
        !fstatat(gc, "reference-roots.lock", &path, AT_SYMLINK_NOFOLLOW) &&
        object_stat_equal(&st, &path);
    int saved = errno;
    if (valid) return fd;
    if (fd >= 0) close(fd);
    errno = saved;
    return fail(error, error_size, "reference roots latch busy or unsafe");
}

static bool lock_matches_at(int directory, const char *name, int fd)
{
    struct stat held, path;
    return directory >= 0 && fd >= 0 && !fstat(fd, &held) &&
        !fstatat(directory, name, &path, AT_SYMLINK_NOFOLLOW) &&
        S_ISREG(held.st_mode) && S_ISREG(path.st_mode) &&
        held.st_dev == path.st_dev && held.st_ino == path.st_ino &&
        held.st_uid == geteuid() && held.st_nlink == 1 && !(held.st_mode & 0077);
}

static bool directory_matches_at(int parent, const char *name, int fd)
{
    struct stat held, path;
    return parent >= 0 && fd >= 0 && !fstat(fd, &held) &&
        !fstatat(parent, name, &path, AT_SYMLINK_NOFOLLOW) &&
        S_ISDIR(held.st_mode) && S_ISDIR(path.st_mode) &&
        held.st_dev == path.st_dev && held.st_ino == path.st_ino &&
        held.st_uid == geteuid() && !(held.st_mode & 0077);
}

static bool same_directory(int a, int b)
{
    struct stat first, second;
    return a >= 0 && b >= 0 && !fstat(a, &first) && !fstat(b, &second) &&
        S_ISDIR(first.st_mode) && S_ISDIR(second.st_mode) &&
        first.st_dev == second.st_dev && first.st_ino == second.st_ino;
}

/* Serializes cooperating scheduler writers without holding the roots latch. */
static int scheduler_lock(const char *root, char *error, size_t error_size)
{
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", true);
    struct stat held, path;
    bool valid = gc >= 0 && !flock(gc, LOCK_EX | LOCK_NB) &&
        !fstat(directory, &held) && !lstat(root, &path) &&
        held.st_dev == path.st_dev && held.st_ino == path.st_ino &&
        directory_matches_at(directory, ".gc", gc);
    if (directory >= 0) close(directory);
    if (valid) return gc;
    if (gc >= 0) close(gc);
    fail(error, error_size, "retirement scheduler lock busy or unsafe");
    return -1;
}

int latcd_retirement_roots_lock(const char *root, int operation,
                                char *error, size_t error_size)
{
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", true);
    int fd = roots_lock_gc(gc, operation, error, error_size);
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    return fd;
}

#ifdef LATCD_RETIREMENT_TESTING
void (*latcd_retirement_test_after_read)(void);
#endif
/* ENOENT is separate from a malformed, unsafe or unreadable root. */
static int read_file(int directory, const char *name, size_t limit,
                     char **contents, size_t *size)
{
    *contents = NULL;
    *size = 0;
    int fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? 1 : -1;
    struct stat before, after, path;
    int result = -1;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) ||
        before.st_uid != geteuid() || before.st_nlink != 1 ||
        (before.st_mode & 0222) || before.st_size <= 0 ||
        (uint64_t)before.st_size > limit) goto out;
    char *data = g_malloc((size_t)before.st_size + 1);
    size_t offset = 0;
    while (offset < (size_t)before.st_size) {
        ssize_t count = read(fd, data + offset, before.st_size - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { g_free(data); goto out; }
        offset += count;
    }
#ifdef LATCD_RETIREMENT_TESTING
    if (latcd_retirement_test_after_read) latcd_retirement_test_after_read();
#endif
    if (fstat(fd, &after) || fstatat(directory, name, &path, AT_SYMLINK_NOFOLLOW) ||
        !object_stat_equal(&before, &after) || !object_stat_equal(&after, &path)) {
        g_free(data);
        goto out;
    }
    data[offset] = 0;
    *contents = data;
    *size = offset;
    result = 0;
out:
    close(fd);
    return result;
}

static bool record_write_fault(const char *point)
{
    const char *fault = getenv("LATCD_TEST_RETIREMENT_IO");
    if (!fault) return false;
    if (g_str_has_prefix(fault, "crash:") && !strcmp(fault + 6, point)) {
        raise(SIGKILL);
        _exit(127);
    }
    if (g_str_has_prefix(fault, "error:") && !strcmp(fault + 6, point)) {
        errno = EIO;
        return true;
    }
    return false;
}

#if defined(LATCD_RETIREMENT_TESTING) && defined(LATCD_CAPACITY_TESTING)
void (*latcd_retirement_test_before_settlement)(void);
void (*latcd_retirement_test_before_page_finish)(LatcdPageBudget *budget);
#endif

static int write_record_kind(int directory, const char *name, GKeyFile *record,
                             bool scheduling, bool fixed_schedule_size, bool recovery,
                             LatcdPageBudget *budget, bool *not_installed)
{
    if (not_installed) *not_installed = true;
    gsize size;
    char *data = g_key_file_to_data(record, &size, NULL);
    if (fixed_schedule_size) {
        /* Fixed-size records let a full store replace an existing hint even
         * when numeric fields grow, without exceeding the replacement reserve. */
        if (size > RETIREMENT_SCHEDULE_RECORD_BYTES - 2) {
            g_free(data);
            errno = EFBIG;
            return -1;
        }
        data = g_realloc(data, RETIREMENT_SCHEDULE_RECORD_BYTES + 1);
        data[size++] = '#';
        memset(data + size, 'x', RETIREMENT_SCHEDULE_RECORD_BYTES - size - 1);
        size = RETIREMENT_SCHEDULE_RECORD_BYTES;
        data[size - 1] = '\n';
        data[size] = 0;
    }
    if (!size || size > RECORD_LIMIT) {
        g_free(data);
        errno = EFBIG;
        return -1;
    }
    LatcdMetadataReservation reservation;
    int reserved;
    if (budget) reserved = latcd_cache_capacity_page_begin(directory, name, size, budget, &reservation);
    else
    reserved = recovery ?
        latcd_cache_capacity_metadata_recovery_begin(directory, name, size, &reservation) : scheduling ?
        latcd_cache_capacity_metadata_schedule_begin(directory, name, size, &reservation) :
        latcd_cache_capacity_metadata_begin(directory, name, size, &reservation);
    if (reserved) {
        g_free(data);
        return -1;
    }
    char *temporary = NULL;
    int fd = -1;
    struct stat target;
    bool anonymous = budget != NULL;
    bool direct_link = anonymous && fixed_schedule_size &&
        fstatat(directory, name, &target, AT_SYMLINK_NOFOLLOW) && errno == ENOENT;
    /* A forked writer may share the parent's random state. Never remove an
     * existing writer's evidence on O_EXCL collision. */
    if (anonymous) fd = openat(directory, ".", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
    for (int attempt = 0; !anonymous && attempt < 16; attempt++) {
        char *uuid = g_uuid_string_random();
        g_free(temporary);
        temporary = g_strdup_printf(".write-%s", uuid);
        g_free(uuid);
        if (latcd_cache_capacity_metadata_stage(&reservation, temporary)) break;
        fd = openat(directory, temporary,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd >= 0 || errno != EEXIST) break;
        latcd_cache_capacity_metadata_unstage(&reservation);
    }
    bool created = fd >= 0;
    bool temporary_owned = created && !anonymous;
    bool replaced = false, leftover = false;
    int result = -1;
    int saved;
    if (fd < 0) goto out;
    if (record_write_fault("created")) goto close_out;
    size_t offset = 0;
    while (offset < size) {
        /* Exercise an interrupted short write without changing normal I/O. */
        size_t chunk = size - offset;
        const char *fault = getenv("LATCD_TEST_RETIREMENT_IO");
        if (!offset && fault && g_str_has_suffix(fault, ":partial-write"))
            chunk = MAX((size_t)1, chunk / 2);
        ssize_t count = write(fd, data + offset, chunk);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) goto close_out;
        offset += count;
        if (record_write_fault("partial-write")) goto close_out;
    }
    if (record_write_fault("written") || fchmod(fd, 0400) ||
        record_write_fault("chmod") || fsync(fd) ||
        record_write_fault("file-synced")) goto close_out;
    if (anonymous) {
        char descriptor[64];
        snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
        if (record_write_fault("closed")) goto close_out;
        if (direct_link) {
            if (linkat(AT_FDCWD, descriptor, directory, name, AT_SYMLINK_FOLLOW)) goto close_out;
        } else {
            bool linked = false;
            for (int attempt = 0; attempt < 16; attempt++) {
                char *uuid = g_uuid_string_random();
                g_free(temporary);
                temporary = g_strdup_printf(".write-%s", uuid);
                g_free(uuid);
                if (latcd_cache_capacity_metadata_stage(&reservation, temporary)) break;
                if (!linkat(AT_FDCWD, descriptor, directory, temporary, AT_SYMLINK_FOLLOW)) {
                    linked = true;
                    temporary_owned = true;
                    break;
                }
                if (errno != EEXIST) break;
                latcd_cache_capacity_metadata_unstage(&reservation);
            }
            if (!linked) goto close_out;
            if (record_write_fault("linked") || record_write_fault("cleanup-sync") ||
                renameat(directory, temporary, directory, name)) goto close_out;
        }
    } else {
        if (close(fd)) { fd = -1; leftover = true; goto out; }
        fd = -1;
        if (record_write_fault("closed") || renameat(directory, temporary, directory, name)) goto out;
    }
    replaced = true;
    if (not_installed) *not_installed = false;
    if (anonymous && reservation.capacity) {
        if (fstat(fd, &reservation.installed_snapshot)) goto close_out;
        reservation.installed_snapshot_present = true;
    }
    if (record_write_fault("renamed") || fsync(directory) ||
        record_write_fault("directory-synced")) goto out;
    result = 0;
close_out:
out:
    saved = errno;
    if (fd >= 0 && close(fd)) leftover = true;
    if (result && temporary_owned && !replaced) {
        if (unlinkat(directory, temporary, 0) ||
            record_write_fault("cleanup-sync") || fsync(directory)) leftover = true;
    }
    if (leftover && not_installed) *not_installed = false;
    /* A failed post-rename sync leaves the durable namespace uncertain. */
    LatcdCacheCapacity *charged_capacity = reservation.capacity;
#if defined(LATCD_RETIREMENT_TESTING) && defined(LATCD_CAPACITY_TESTING)
    if (latcd_retirement_test_before_settlement) latcd_retirement_test_before_settlement();
#endif
    latcd_cache_capacity_metadata_finish(&reservation, replaced,
                                         leftover || (replaced && result));
    if (!recovery && charged_capacity && !latcd_cache_capacity_poll(charged_capacity)) {
        if (!result) saved = EIO;
        result = -1;
    }
    g_free(temporary);
    g_free(data);
    errno = saved;
    return result;
}

static int write_record(int directory, const char *name, GKeyFile *record)
{
    return write_record_kind(directory, name, record, false, false, false, NULL, NULL);
}

static int write_recovery_record(int directory, const char *name, GKeyFile *record)
{
    return write_record_kind(directory, name, record, false, false, true, NULL, NULL);
}

static int retirement_clock(char **boot, uint64_t *stamp)
{
    struct timespec now;
    gsize size = 0;
    *boot = NULL;
    if (clock_gettime(CLOCK_BOOTTIME, &now) ||
        !g_file_get_contents("/proc/sys/kernel/random/boot_id", boot, &size, NULL))
        goto failed;
    if (now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000 ||
        (uint64_t)now.tv_sec > (UINT64_MAX - (uint64_t)now.tv_nsec / 1000) / 1000000 ||
        (size != 36 && size != 37) || memchr(*boot, 0, size) ||
        (size == 37 && (*boot)[36] != '\n')) goto failed;
    (*boot)[36] = 0;
    if (!g_uuid_string_is_valid(*boot)) goto failed;
    *stamp = (uint64_t)now.tv_sec * 1000000 + now.tv_nsec / 1000;
    return 0;
failed:
    g_free(*boot);
    *boot = NULL;
    errno = EIO;
    return -1;
}

int latcd_retirement_round_sample(const char *root, char boot[37], uint64_t *cutoff,
                                  char *error, size_t error_size)
{
    if (!root || !boot || !cutoff)
        return fail(error, error_size, "invalid retirement round sample");
    boot[0] = 0;
    *cutoff = 0;
    int roots = latcd_retirement_roots_lock(root, LOCK_EX | LOCK_NB, error, error_size);
    if (roots < 0) return -1;
    char *id = NULL;
    uint64_t stamp = 0;
    int result = retirement_clock(&id, &stamp);
    if (!result) {
        memcpy(boot, id, 37);
        *cutoff = stamp;
    }
    g_free(id);
    close(roots);
    return result ? fail(error, error_size, "cannot sample retirement round clock") : 0;
}

int latcd_retirement_round_restore(LatcdRetirementRound *round,
                                   const char *boot, uint64_t cutoff)
{
    if (!round || !boot || strlen(boot) != 36 || !g_uuid_string_is_valid(boot) || !cutoff)
        return -1;
    memcpy(round->boot, boot, 37);
    round->cutoff = cutoff;
    return 0;
}

int latcd_retirement_round_complete(LatcdRetirementRound *round,
                                    const char *boot, uint64_t observed_cutoff)
{
    if (!round || !boot || strlen(boot) != 36 || !g_uuid_string_is_valid(boot) || !observed_cutoff ||
        strcmp(round->boot, boot) || observed_cutoff <= round->cutoff) return -1;
    round->cutoff = observed_cutoff;
    return 0;
}

int latcd_retirement_page_select(const char *const *names, size_t count,
                                 const char *after, LatcdRetirementPage *page)
{
    if (!page || (!names && count) ||
        (after && strlen(after) >= sizeof(page->next_cursor)))
        return -1;
    memset(page, 0, sizeof(*page));
    for (size_t i = 0; i < count; i++) {
        if (!names[i] || !*names[i] || strlen(names[i]) >= sizeof(page->next_cursor) ||
            (i && strcmp(names[i - 1], names[i]) >= 0)) return -1;
        if (page->count < 128 && (!after || strcmp(names[i], after) > 0)) {
            g_strlcpy(page->next_cursor, names[i], sizeof(page->next_cursor));
            page->count++;
        }
    }
    return page->count ? 1 : 0;
}

int latcd_retirement_page_observe(LatcdRetirementPageDeadline *deadlines,
                                  size_t count, const char *name, uint64_t deadline)
{
    if (!deadlines || count > 128 || !name || !deadline) return -1;
    for (size_t i = 0; i < count; i++) {
        if (!strcmp(deadlines[i].name, name)) {
            if (deadline > deadlines[i].deadline) deadlines[i].deadline = deadline;
            return 0;
        }
    }
    return 1;
}

int latcd_retirement_page_names(const char *const *names, size_t count,
                                const LatcdRetirementPage *page,
                                char selected[128][138])
{
    if (!names || !page || !selected || page->count > 128) return -1;
    if (!page->count) return page->next_cursor[0] ? -1 : 0;
    const char *after = NULL;
    size_t end = count;
    for (size_t i = 0; i < count; i++) {
        if (!names[i]) return -1;
        if (after && strcmp(names[i], after) <= 0) return -1;
        if (!strcmp(names[i], page->next_cursor)) end = i;
        after = names[i];
    }
    if (end == count || end + 1 < page->count) return -1;
    size_t start = end + 1 - page->count;
    for (unsigned i = 0; i < page->count; i++) {
        if (strlen(names[start + i]) >= sizeof(selected[i])) return -1;
        g_strlcpy(selected[i], names[start + i], sizeof(selected[i]));
    }
    return page->count;
}

int latcd_retirement_page_state_valid(const LatcdRetirementPageState *state)
{
    if (!state || !state->cache_device || !state->cache_inode || !state->grace_us || !state->round_cutoff ||
        strnlen(state->boot, sizeof(state->boot)) != 36 || !g_uuid_string_is_valid(state->boot) ||
        state->count > 128 || (state->count && !state->cursor[0]) ||
        (state->committed_pending && !state->count) ||
        strnlen(state->committed_cursor, sizeof(state->committed_cursor)) >= sizeof(state->committed_cursor) ||
        strnlen(state->cursor, sizeof(state->cursor)) >= sizeof(state->cursor)) return -1;
    for (unsigned i = 0; i < state->count; i++) {
        if (state->committed_pending ? (state->results[i] != 1 && state->results[i] != 2) :
                                       state->results[i] != 0) return -1;
        if (!state->entries[i].name[0] ||
            strnlen(state->entries[i].name, sizeof(state->entries[i].name)) >= sizeof(state->entries[i].name) ||
            !state->entries[i].deadline ||
            !state->entries[i].enqueued || state->entries[i].last_attempt > state->sequence ||
            state->entries[i].busy_count > 7) return -1;
        if (i && strcmp(state->entries[i - 1].name, state->entries[i].name) >= 0) return -1;
        if (state->committed_cursor[0] &&
            strcmp(state->entries[i].name, state->committed_cursor) <= 0) return -1;
    }
    if (state->count) {
        if (strcmp(state->entries[state->count - 1].name, state->cursor)) return -1;
    } else if (state->cursor[0]) return -1;
    return 0;
}

static void page_identity_u64(GChecksum *checksum, uint64_t value)
{
    uint8_t bytes[8];
    for (unsigned i = 0; i < sizeof(bytes); i++)
        bytes[i] = (uint8_t)(value >> (56 - i * 8));
    g_checksum_update(checksum, bytes, sizeof(bytes));
}

static void page_identity_string(GChecksum *checksum, const char *value)
{
    size_t length = strlen(value);
    page_identity_u64(checksum, length);
    g_checksum_update(checksum, (const guchar *)value, length);
}

int latcd_retirement_page_identity(const LatcdRetirementPageState *state,
                                   uint8_t digest[32])
{
    if (!digest) return -1;
    memset(digest, 0, 32);
    if (latcd_retirement_page_state_valid(state) || !state->count ||
        (state->committed_cursor[0] && !page_object_name_valid(state->committed_cursor)))
        return -1;
    for (unsigned i = 0; i < state->count; i++)
        if (!page_object_name_valid(state->entries[i].name)) return -1;
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    static const char domain[] = "latcd-retirement-page-v1";
    g_checksum_update(checksum, (const guchar *)domain, sizeof(domain));
    page_identity_u64(checksum, state->cache_device);
    page_identity_u64(checksum, state->cache_inode);
    page_identity_string(checksum, state->boot);
    page_identity_u64(checksum, state->grace_us);
    page_identity_u64(checksum, state->round_cutoff);
    page_identity_string(checksum, state->committed_cursor);
    page_identity_u64(checksum, state->count);
    for (unsigned i = 0; i < state->count; i++) {
        page_identity_string(checksum, state->entries[i].name);
        page_identity_u64(checksum, state->entries[i].deadline);
    }
    gsize length = 32;
    g_checksum_get_digest(checksum, digest, &length);
    g_checksum_free(checksum);
    return length == 32 ? 0 : -1;
}

int latcd_retirement_page_budget_identity(const LatcdRetirementPageState *state,
                                          uint8_t digest[32])
{
    if (!digest) return -1;
    memset(digest, 0, 32);
    uint8_t membership[32];
    if (!state || latcd_retirement_page_identity(state, membership))
        return -1;
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    static const char domain[] = "latcd-retirement-budget-v1";
    g_checksum_update(checksum, (const guchar *)domain, sizeof(domain));
    g_checksum_update(checksum, membership, sizeof(membership));
    page_identity_u64(checksum, state->sequence);
    for (unsigned i = 0; i < state->count; i++)
        page_identity_u64(checksum, state->entries[i].enqueued);
    gsize length = 32;
    g_checksum_get_digest(checksum, digest, &length);
    g_checksum_free(checksum);
    return length == 32 ? 0 : -1;
}

static int page_snapshot_identity(const LatcdRetirementPageState *state, uint8_t digest[32])
{
    uint8_t binding[32];
    if (latcd_retirement_page_budget_identity(state, binding)) return -1;
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    static const char domain[] = "latcd-retirement-snapshot-v1";
    g_checksum_update(checksum, (const guchar *)domain, sizeof(domain));
    g_checksum_update(checksum, binding, sizeof(binding));
    page_identity_u64(checksum, state->committed_pending);
    for (unsigned i = 0; i < state->count; i++) {
        page_identity_u64(checksum, state->entries[i].last_attempt);
        page_identity_u64(checksum, state->entries[i].retry_at);
        page_identity_u64(checksum, state->entries[i].busy_count);
        page_identity_u64(checksum, state->results[i]);
    }
    gsize length = 32;
    g_checksum_get_digest(checksum, digest, &length);
    g_checksum_free(checksum);
    return length == 32 ? 0 : -1;
}

static bool record_string_is(GKeyFile *record, const char *group,
                             const char *key, const char *expected);
static bool record_uint64(GKeyFile *record, const char *group,
                          const char *key, uint64_t *value);
static bool exact_keys(GKeyFile *record, const char *group,
                       const char *const *expected, size_t count);
static int queue_watch_fd(int notify, int fd, uint32_t mask);
static bool queue_watch_clean(int notify);

static bool page_state_shape(GKeyFile *record, LatcdRetirementPageState *state)
{
    const char *queue_fields[] = {"version", "cache_device", "cache_inode", "grace_us",
                                  "boot", "round_cutoff", "cursor", "sequence", "count"};
    const char *queue_fields_v3[] = {"version", "cache_device", "cache_inode", "grace_us",
        "boot", "round_cutoff", "committed_cursor", "cursor", "sequence", "count"};
    const char *queue_fields_v4[] = {"version", "cache_device", "cache_inode", "grace_us",
        "boot", "round_cutoff", "committed_cursor", "cursor", "sequence", "count", "pending"};
    const char *queue_fields_v6[] = {"version", "cache_device", "cache_inode", "grace_us",
        "boot", "round_cutoff", "committed_cursor", "cursor", "sequence", "count", "pending",
        "budget_protocol", "budget_identity"};
    const char *queue_fields_v7[] = {"version", "cache_device", "cache_inode", "grace_us",
        "boot", "round_cutoff", "committed_cursor", "cursor", "sequence", "count", "pending",
        "budget_protocol", "budget_identity", "snapshot_identity"};
    const char *entry_fields[] = {"name", "deadline", "enqueued", "last_attempt",
                                  "retry_at", "busy_count"};
    const char *entry_fields_v5[] = {"name", "deadline", "enqueued", "last_attempt",
                                  "retry_at", "busy_count", "result"};
    gsize groups_count;
    char **groups = g_key_file_get_groups(record, &groups_count);
    bool v3 = record_string_is(record, "page", "version", "3");
    bool v4 = record_string_is(record, "page", "version", "4");
    bool v5 = record_string_is(record, "page", "version", "5");
    bool v6 = record_string_is(record, "page", "version", "6");
    bool v7 = record_string_is(record, "page", "version", "7");
    bool valid = groups_count && !strcmp(groups[0], "page") &&
        (v7 ? exact_keys(record, "page", queue_fields_v7, G_N_ELEMENTS(queue_fields_v7)) :
         v6 ? exact_keys(record, "page", queue_fields_v6, G_N_ELEMENTS(queue_fields_v6)) :
         (v4 || v5) ? exact_keys(record, "page", queue_fields_v4, G_N_ELEMENTS(queue_fields_v4)) :
         v3 ? exact_keys(record, "page", queue_fields_v3, G_N_ELEMENTS(queue_fields_v3)) :
              exact_keys(record, "page", queue_fields, G_N_ELEMENTS(queue_fields)));
    g_strfreev(groups);
    if (!valid || (!v7 && !v6 && !v5 && !v4 && !v3 && !record_string_is(record, "page", "version", "2")) ||
        !record_uint64(record, "page", "cache_device", &state->cache_device) ||
        !record_uint64(record, "page", "cache_inode", &state->cache_inode) ||
        !record_uint64(record, "page", "grace_us", &state->grace_us) ||
        !record_uint64(record, "page", "round_cutoff", &state->round_cutoff) ||
        !record_uint64(record, "page", "sequence", &state->sequence)) return false;
    char *boot = g_key_file_get_string(record, "page", "boot", NULL);
    char *cursor = g_key_file_get_string(record, "page", "cursor", NULL);
    char *committed = (v3 || v4 || v5 || v6 || v7) ? g_key_file_get_string(record, "page", "committed_cursor", NULL) : g_strdup("");
    uint64_t count, pending = 0;
    valid = boot && cursor && committed && strlen(committed) < sizeof(state->committed_cursor) &&
        (!(v4 || v5 || v6 || v7) || (record_uint64(record, "page", "pending", &pending) && pending <= 1)) &&
        (!v4 || !pending) &&
        record_uint64(record, "page", "count", &count) &&
        count <= 128 &&
        strlen(boot) == 36 && strlen(cursor) < sizeof(state->cursor);
    if (valid) {
        g_strlcpy(state->boot, boot, sizeof(state->boot));
        g_strlcpy(state->cursor, cursor, sizeof(state->cursor));
        g_strlcpy(state->committed_cursor, committed, sizeof(state->committed_cursor));
        state->count = (unsigned)count;
        state->committed_pending = pending;
    }
    if (valid && groups_count != (gsize)state->count + 1) valid = false;
    g_free(boot); g_free(cursor); g_free(committed);
    for (unsigned i = 0; valid && i < state->count; i++) {
        char group[32];
        snprintf(group, sizeof(group), "entry%u", i);
        uint64_t busy, result = 0;
        char *name = g_key_file_get_string(record, group, "name", NULL);
        valid = ((v5 || v6 || v7) ? exact_keys(record, group, entry_fields_v5, G_N_ELEMENTS(entry_fields_v5)) :
                      exact_keys(record, group, entry_fields, G_N_ELEMENTS(entry_fields))) &&
            (!(v5 || v6 || v7) || (record_uint64(record, group, "result", &result) && result <= 2)) &&
            name && strlen(name) < sizeof(state->entries[i].name) &&
            record_uint64(record, group, "deadline", &state->entries[i].deadline) &&
            record_uint64(record, group, "enqueued", &state->entries[i].enqueued) &&
            record_uint64(record, group, "last_attempt", &state->entries[i].last_attempt) &&
            record_uint64(record, group, "retry_at", &state->entries[i].retry_at) &&
            record_uint64(record, group, "busy_count", &busy) && busy <= 7;
        if (valid) {
            g_strlcpy(state->entries[i].name, name, sizeof(state->entries[i].name));
            state->entries[i].busy_count = busy;
            state->results[i] = result;
        }
        g_free(name);
    }
    if (!valid || latcd_retirement_page_state_valid(state)) return false;
    if (v6 || v7) {
        uint8_t digest[32];
        char expected[65];
        char *identity = g_key_file_get_string(record, "page", "budget_identity", NULL);
        valid = record_string_is(record, "page", "budget_protocol", "1") &&
            !latcd_retirement_page_budget_identity(state, digest);
        if (valid) {
            for (unsigned i = 0; i < 32; i++) snprintf(expected + 2 * i, 3, "%02x", digest[i]);
            valid = identity && !strcmp(identity, expected);
        }
        g_free(identity);
        if (!valid) return false;
        if (v7) {
            identity = g_key_file_get_string(record, "page", "snapshot_identity", NULL);
            valid = !page_snapshot_identity(state, digest);
            if (valid) {
                for (unsigned i = 0; i < 32; i++) snprintf(expected + 2 * i, 3, "%02x", digest[i]);
                valid = identity && !strcmp(identity, expected);
            }
            g_free(identity);
            if (!valid) return false;
        }
        state->budget_bound = true;
    }
    return true;
}

static int page_state_store_fd(int root_fd, int gc, const LatcdRetirementPageState *state,
                               LatcdPageBudget *budget, bool *not_installed)
{
    if (not_installed) *not_installed = true;
    int result = -1;
    GKeyFile *record = g_key_file_new();
    struct stat cache;
    uint8_t binding[32];
    if (gc < 0 || latcd_retirement_page_state_valid(state) ||
        (state->budget_bound && !budget) ||
        (budget && state->count && (!budget->page_identity_bound ||
         latcd_retirement_page_budget_identity(state, binding) ||
         memcmp(binding, budget->page_identity, sizeof(binding)))) ||
        (budget && !budget->page_identity_bound) || fstat(root_fd, &cache) ||
        state->cache_device != (uint64_t)cache.st_dev ||
        state->cache_inode != (uint64_t)cache.st_ino) goto out;
    g_key_file_set_integer(record, "page", "version", budget && state->count ? 7 : 5);
    if (budget && state->count) {
        char identity[65];
        for (unsigned i = 0; i < 32; i++) snprintf(identity + 2 * i, 3, "%02x", binding[i]);
        g_key_file_set_integer(record, "page", "budget_protocol", 1);
        g_key_file_set_string(record, "page", "budget_identity", identity);
        if (page_snapshot_identity(state, binding)) goto out;
        for (unsigned i = 0; i < 32; i++) snprintf(identity + 2 * i, 3, "%02x", binding[i]);
        g_key_file_set_string(record, "page", "snapshot_identity", identity);
    }
    g_key_file_set_uint64(record, "page", "cache_device", state->cache_device);
    g_key_file_set_uint64(record, "page", "cache_inode", state->cache_inode);
    g_key_file_set_uint64(record, "page", "grace_us", state->grace_us);
    g_key_file_set_uint64(record, "page", "round_cutoff", state->round_cutoff);
    g_key_file_set_string(record, "page", "boot", state->boot);
    g_key_file_set_string(record, "page", "committed_cursor", state->committed_cursor);
    g_key_file_set_string(record, "page", "cursor", state->cursor);
    g_key_file_set_uint64(record, "page", "sequence", state->sequence);
    g_key_file_set_uint64(record, "page", "count", state->count);
    g_key_file_set_integer(record, "page", "pending", state->committed_pending);
    for (unsigned i = 0; i < state->count; i++) {
        char group[32];
        snprintf(group, sizeof(group), "entry%u", i);
        g_key_file_set_string(record, group, "name", state->entries[i].name);
        g_key_file_set_uint64(record, group, "deadline", state->entries[i].deadline);
        g_key_file_set_uint64(record, group, "enqueued", state->entries[i].enqueued);
        g_key_file_set_uint64(record, group, "last_attempt", state->entries[i].last_attempt);
        g_key_file_set_uint64(record, group, "retry_at", state->entries[i].retry_at);
        g_key_file_set_uint64(record, group, "busy_count", state->entries[i].busy_count);
        g_key_file_set_uint64(record, group, "result", state->results[i]);
    }
    result = write_record_kind(gc, "retirement-page.ini", record, true, false, false, budget, not_installed);
out:
    g_key_file_unref(record);
    return result;
}

#ifdef LATCD_RETIREMENT_TESTING
int latcd_retirement_page_state_store(const char *root,
                                      const LatcdRetirementPageState *state,
                                      char *error, size_t error_size)
{
    if (!root || !state) return fail(error, error_size, "invalid retirement page state");
    int scheduler = scheduler_lock(root, error, error_size);
    if (scheduler < 0) return -1;
    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = root_fd < 0 ? -1 : open_directory(root_fd, ".gc", true);
    int result = same_directory(scheduler, gc) ? page_state_store_fd(root_fd, gc, state, NULL, NULL) : -1;
    if (gc >= 0) close(gc);
    if (root_fd >= 0) close(root_fd);
    close(scheduler);
    return result ? fail(error, error_size, "cannot persist retirement page state") : 0;
}
#endif

static int page_state_load(const char *root, LatcdRetirementPageState *state,
                           bool *legacy, char *error, size_t error_size)
{
    if (!root || !state) return fail(error, error_size, "invalid retirement page state");
    if (legacy) *legacy = false;
    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = root_fd < 0 ? -1 : open_directory(root_fd, ".gc", false);
    struct stat cache;
    char *raw = NULL;
    size_t size;
    GKeyFile *record = g_key_file_new();
    memset(state, 0, sizeof(*state));
    int result = -1;
    if (gc < 0) {
        if (errno == ENOENT) result = 1;
        goto out;
    }
    int status = read_file(gc, "retirement-page.ini", RECORD_LIMIT, &raw, &size);
    if (status == 1) { result = 1; goto out; }
    result = status || fstat(root_fd, &cache) || memchr(raw, 0, size) ||
        !g_key_file_load_from_data(record, raw, size, 0, NULL) ||
        !page_state_shape(record, state) ||
        state->cache_device != (uint64_t)cache.st_dev ||
        state->cache_inode != (uint64_t)cache.st_ino ? -1 : 0;
    if (!result && legacy) *legacy = record_string_is(record, "page", "version", "2");
out:
    g_free(raw); g_key_file_unref(record);
    if (gc >= 0) close(gc);
    if (root_fd >= 0) close(root_fd);
    if (result) memset(state, 0, sizeof(*state));
    return result < 0 ? fail(error, error_size, "retirement page state unsafe or incompatible") : result;
}

int latcd_retirement_page_state_load(const char *root, LatcdRetirementPageState *state,
                                     char *error, size_t error_size)
{
    return page_state_load(root, state, NULL, error, error_size);
}

static bool gc_has_no_partial_records(int gc)
{
    struct stat before, after;
    if (fstat(gc, &before)) return false;
    int scan = openat(gc, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *dir = scan < 0 ? NULL : fdopendir(scan);
    if (!dir) { if (scan >= 0) close(scan); return false; }
    bool valid = true;
    unsigned visited = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) { if (errno) valid = false; break; }
        if (++visited > 100000 || g_str_has_prefix(entry->d_name, ".write-")) {
            valid = false;
            break;
        }
    }
    if (fstat(gc, &after) || !object_stat_equal(&before, &after)) valid = false;
    closedir(dir);
    return valid;
}

int latcd_retirement_startup_records_check(const char *root, char *error, size_t error_size)
{
    if (!root) return fail(error, error_size, "invalid retirement startup root");
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", false);
    int gc_errno = errno;
    struct stat held, path;
    bool valid = directory >= 0 && !fstat(directory, &held) && !lstat(root, &path) &&
        held.st_dev == path.st_dev && held.st_ino == path.st_ino;
    if (valid && gc < 0) valid = gc_errno == ENOENT;
    const char *names[] = {"transactions", "tombstones", "retirement-schedule"};
    for (unsigned i = 0; valid && gc >= 0 && i < G_N_ELEMENTS(names); i++) {
        int store = open_directory(gc, names[i], false);
        if (store < 0) { valid = errno == ENOENT; continue; }
        valid = directory_matches_at(gc, names[i], store) && gc_has_no_partial_records(store) &&
            directory_matches_at(gc, names[i], store);
        close(store);
    }
    if (valid && gc >= 0) valid = directory_matches_at(directory, ".gc", gc);
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    return valid ? 0 : fail(error, error_size, "incomplete or unsafe retirement startup records");
}

int latcd_retirement_page_startup_check(const char *root, char *error, size_t error_size)
{
    if (!root) return fail(error, error_size, "invalid retirement startup root");
    int scheduler = scheduler_lock(root, error, error_size);
    if (scheduler < 0) return -1;
    LatcdRetirementPageState state;
    bool legacy = false;
    int status = page_state_load(root, &state, &legacy, error, error_size);
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", false);
    struct stat held, path;
    bool valid = status >= 0 && gc >= 0 && same_directory(scheduler, gc) &&
        !fstat(directory, &held) && !lstat(root, &path) &&
        held.st_dev == path.st_dev && held.st_ino == path.st_ino &&
        directory_matches_at(directory, ".gc", gc) && gc_has_no_partial_records(gc) &&
        (status == 1 || (!legacy && !state.count && !state.committed_pending));
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    close(scheduler);
    return valid ? 0 : fail(error, error_size,
        "retirement page budget recovery unavailable or checkpoint unsafe");
}

static int schedule_page_results(const char *root, uint64_t now_us,
                                 const LatcdRetirementPageState *page,
                                 uint8_t *results, LatcdRetirementPageInventory *inventory,
                                 char *error, size_t error_size);

static int page_stage(const char *root, const LatcdRetirementPageState *page,
                      LatcdCacheCapacity *capacity, uint64_t limit, LatcdPageBudget *budget,
                      char *error, size_t error_size)
{
    uint8_t identity[32];
    if (!root || !page || (!!capacity != !!budget) || page->budget_bound ||
        latcd_retirement_page_identity(page, identity))
        return fail(error, error_size, "invalid retirement page stage");
    int scheduler = scheduler_lock(root, error, error_size);
    if (scheduler < 0) return -1;
    LatcdRetirementPageState previous;
    bool legacy = false;
    char *boot = NULL;
    uint64_t now = 0;
    int directory = -1, gc = -1, result = -1;
    if (retirement_clock(&boot, &now) ||
        latcd_retirement_page_state_compatible(page, boot, page->grace_us, now) ||
        page_state_load(root, &previous, &legacy, error, error_size) || legacy ||
        previous.committed_pending || previous.count || previous.cursor[0] ||
        page->committed_pending ||
        previous.cache_device != page->cache_device || previous.cache_inode != page->cache_inode ||
        previous.grace_us != page->grace_us || previous.round_cutoff != page->round_cutoff ||
        strcmp(previous.boot, page->boot) || strcmp(previous.committed_cursor, page->committed_cursor) ||
        page->sequence < previous.sequence) goto out;
    directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    gc = directory < 0 ? -1 : open_directory(directory, ".gc", false);
    struct stat held, path;
    if (!same_directory(scheduler, gc) || fstat(directory, &held) || lstat(root, &path) ||
        held.st_dev != path.st_dev || held.st_ino != path.st_ino ||
        !directory_matches_at(directory, ".gc", gc)) goto out;
    if (budget) {
        LatcdRetirementPageInventory inventory = {0};
        uint8_t results[128] = {0}, binding[32];
        uint64_t bytes;
        int matching = latcd_cache_capacity_open_matching_root(capacity, root, directory);
        if (matching < 0) goto out;
        close(matching);
        if (schedule_page_results(root, now, page, results, &inventory, error, error_size) < 0 ||
            latcd_retirement_page_budget_identity(page, binding) ||
            latcd_retirement_page_budget_estimate(page, results, &inventory, &bytes) ||
            latcd_cache_capacity_reserve_page(capacity, bytes, limit, binding, budget)) goto out;
        bool not_installed = false;
        result = page_state_store_fd(directory, gc, page, budget, &not_installed);
        if (result && not_installed) {
            int saved = errno;
            latcd_cache_capacity_cancel_page(capacity, budget);
            errno = saved;
        }
    } else result = page_state_store_fd(directory, gc, page, NULL, NULL);
out:
    g_free(boot);
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    close(scheduler);
    return result ? fail(error, error_size, "retirement page stage failed; reload") : 0;
}

int latcd_retirement_page_stage(const char *root, const LatcdRetirementPageState *page,
                                char *error, size_t error_size)
{
    return page_stage(root, page, NULL, 0, NULL, error, error_size);
}

int latcd_retirement_page_stage_budgeted(const char *root, const LatcdRetirementPageState *page,
                                LatcdCacheCapacity *capacity, uint64_t limit, LatcdPageBudget *budget,
                                char *error, size_t error_size)
{
    if (!capacity || !budget) return fail(error, error_size, "missing page capacity or budget");
    return page_stage(root, page, capacity, limit, budget, error, error_size);
}

int latcd_retirement_page_round_begin(const char *root, uint64_t grace_us,
                                      LatcdRetirementPageState *state,
                                      char *error, size_t error_size)
{
    if (!root || !state || !grace_us)
        return fail(error, error_size, "invalid retirement round input");
    memset(state, 0, sizeof(*state));
    int scheduler = scheduler_lock(root, error, error_size);
    if (scheduler < 0) return -1;
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", true);
    int roots = roots_lock_gc(gc, LOCK_EX | LOCK_NB, error, error_size);
    int result = -1;
    char *boot = NULL;
    uint64_t cutoff = 0;
    struct stat cache, held_gc, held_lock, path;
    if (roots < 0 || !same_directory(scheduler, gc) || fstat(directory, &cache) || fstat(gc, &held_gc) ||
        fstat(roots, &held_lock) ||
        !fstatat(gc, "retirement-page.ini", &path, AT_SYMLINK_NOFOLLOW) || errno != ENOENT ||
        retirement_clock(&boot, &cutoff) || !cutoff) goto out;
    LatcdRetirementPageState next = {0};
    next.cache_device = cache.st_dev;
    next.cache_inode = cache.st_ino;
    next.grace_us = grace_us;
    next.round_cutoff = cutoff;
    memcpy(next.boot, boot, sizeof(next.boot));
    if (page_state_store_fd(directory, gc, &next, NULL, NULL) ||
        lstat(root, &path) || !object_stat_equal(&cache, &path) ||
        fstatat(directory, ".gc", &path, AT_SYMLINK_NOFOLLOW) ||
        path.st_dev != held_gc.st_dev || path.st_ino != held_gc.st_ino ||
        fstatat(gc, "reference-roots.lock", &path, AT_SYMLINK_NOFOLLOW) ||
        !object_stat_equal(&held_lock, &path)) goto out;
    *state = next;
    result = 0;
out:
    g_free(boot);
    if (directory >= 0) close(directory);
    if (roots >= 0) close(roots);
    if (gc >= 0) close(gc);
    close(scheduler);
    return result ? fail(error, error_size, "cannot begin retirement round; reload state") : 0;
}

int latcd_retirement_page_state_compatible(const LatcdRetirementPageState *state,
                                           const char *boot, uint64_t grace_us, uint64_t now_us)
{
    if (!state || !boot || !grace_us || !now_us || latcd_retirement_page_state_valid(state) ||
        state->round_cutoff > now_us || strcmp(state->boot, boot) || state->grace_us != grace_us)
        return 1;
    for (unsigned i = 0; i < state->count; i++) {
        const LatcdRetirementPageDeadline *entry = &state->entries[i];
        if (entry->enqueued > now_us ||
            (entry->retry_at > now_us && entry->retry_at - now_us > RETIREMENT_BUSY_MAX_US))
            return 1;
    }
    return 0;
}

int latcd_retirement_page_state_resume(const char *root, const char *boot,
                                       uint64_t grace_us, uint64_t now_us, LatcdRetirementPageState *state,
                                       char *error, size_t error_size)
{
    int result = latcd_retirement_page_state_load(root, state, error, error_size);
    if (result <= 0 && result == 0 &&
        latcd_retirement_page_state_compatible(state, boot, grace_us, now_us)) {
        memset(state, 0, sizeof(*state));
        return fail(error, error_size, "retirement page state incompatible with runtime");
    }
    if (!result) {
        bool valid = (!state->committed_cursor[0] || page_object_name_valid(state->committed_cursor)) &&
            (!state->cursor[0] || page_object_name_valid(state->cursor));
        for (unsigned i = 0; valid && i < state->count; i++)
            valid = page_object_name_valid(state->entries[i].name);
        if (!valid) {
            memset(state, 0, sizeof(*state));
            return fail(error, error_size, "invalid retirement page object name");
        }
    }
    return result;
}

static int retirement_schedule_access(const char *root, const char *boot,
                                    uint64_t grace_us, uint64_t now_us,
                                    uint64_t sequence,
                                    const LatcdRetirementPageDeadline *entry,
                                    bool loading, uint64_t *loaded_sequence,
                                    LatcdRetirementPageDeadline *loaded_entry,
                                    LatcdRetirementPageState *merge,
                                    const uint8_t *page_identity, LatcdRetirementResultKind kind,
                                    LatcdRetirementResultKind *loaded_kind,
                                    const LatcdRetirementPageState *check_page,
                                    const LatcdRetirementPageState *expected_page,
                                    uint8_t *page_results,
                                    LatcdRetirementPageDeadline *page_schedule,
                                    LatcdRetirementPageInventory *inventory,
                                    LatcdPageBudget *budget,
                                    int scheduler,
                                    char *error, size_t error_size)
{
    if (!root || !boot || !g_uuid_string_is_valid(boot) || !grace_us || !now_us ||
        (!merge && !check_page && (!entry || strnlen(entry->name, sizeof(entry->name)) == sizeof(entry->name) ||
        !page_object_name_valid(entry->name))) || (!loading && (!entry->enqueued ||
        entry->enqueued > now_us || entry->last_attempt > sequence ||
        entry->busy_count > 7 || (entry->retry_at > now_us &&
        entry->retry_at - now_us > RETIREMENT_BUSY_MAX_US))) ||
        (page_identity && ((!loading && kind != LATCD_RETIREMENT_RESULT_DONE &&
                            kind != LATCD_RETIREMENT_RESULT_DEFERRED) ||
                           (loading && ((!loaded_kind && !check_page) || merge)))))
        return fail(error, error_size, "invalid retirement schedule entry");
    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = root_fd < 0 ? -1 : open_directory(root_fd, ".gc", false);
    int store = gc < 0 ? -1 : open_directory(gc, "retirement-schedule", false);
    struct stat cache, held_store, after_store, path;
    int scan = store < 0 ? -1 : openat(store, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *dir = scan < 0 ? NULL : fdopendir(scan);
    if (scan >= 0 && !dir) close(scan);
    int watch = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    int result = -1;
    unsigned count = 0;
    uint64_t bytes = 0;
    uint64_t replaced_bytes = 0;
    bool found = false;
    bool identical_result = false;
    uint64_t saved_sequence = 0;
    LatcdRetirementResultKind saved_kind = 0;
    bool page_seen[128] = {0};
    unsigned page_found = 0;
    LatcdRetirementPageDeadline saved = {0};
    char *filename = merge || check_page ? NULL : g_strconcat(entry->name, ".ini", NULL);
    GKeyFile *output = g_key_file_new();
    if (!dir || watch < 0 || queue_watch_fd(watch, store,
        IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_MODIFY |
        IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR) ||
        fstat(root_fd, &cache) || fstat(store, &held_store) ||
        (!loading && !same_directory(scheduler, gc)) ||
        (expected_page && (expected_page->cache_device != (uint64_t)cache.st_dev ||
                           expected_page->cache_inode != (uint64_t)cache.st_ino))) goto out;
    char page_hex[65] = {0};
    if (page_identity)
        for (unsigned i = 0; i < 32; i++) snprintf(page_hex + i * 2, 3, "%02x", page_identity[i]);
    const char *keys[] = {"version", "device", "inode", "boot", "grace", "name",
                          "sequence", "enqueued", "last_attempt", "retry_at", "busy_count"};
    const char *keys_v2[] = {"version", "device", "inode", "boot", "grace", "name",
                          "sequence", "enqueued", "last_attempt", "retry_at", "busy_count",
                          "page_identity", "result"};
    for (;;) {
        errno = 0;
        struct dirent *item = readdir(dir);
        if (!item) { if (errno) goto out; break; }
        if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, "..")) continue;
        char *raw = NULL;
        size_t size = 0;
        GKeyFile *record = g_key_file_new();
        gsize groups_count = 0;
        uint64_t device, inode, grace, seq, enqueued, attempted, retry, busy;
        bool valid = ++count <= RETIREMENT_SCHEDULE_LIMIT &&
            !read_file(store, item->d_name, 1024, &raw, &size) &&
            size <= RETIREMENT_SCHEDULE_BYTES - bytes && !memchr(raw, 0, size) &&
            g_key_file_load_from_data(record, raw, size, 0, NULL);
        char **groups = valid ? g_key_file_get_groups(record, &groups_count) : NULL;
        char *saved_boot = valid ? g_key_file_get_string(record, "schedule", "boot", NULL) : NULL;
        char *name = valid ? g_key_file_get_string(record, "schedule", "name", NULL) : NULL;
        char *expected = name ? g_strconcat(name, ".ini", NULL) : NULL;
        bool v2 = valid && record_string_is(record, "schedule", "version", "2");
        char *identity = v2 ? g_key_file_get_string(record, "schedule", "page_identity", NULL) : NULL;
        char *saved_result = v2 ? g_key_file_get_string(record, "schedule", "result", NULL) : NULL;
        bool identity_valid = identity && strlen(identity) == 64;
        for (unsigned i = 0; identity_valid && i < 64; i++)
            identity_valid = (identity[i] >= '0' && identity[i] <= '9') ||
                             (identity[i] >= 'a' && identity[i] <= 'f');
        valid = valid && groups_count == 1 && !strcmp(groups[0], "schedule") &&
            ((v2 && exact_keys(record, "schedule", keys_v2, G_N_ELEMENTS(keys_v2)) &&
              identity_valid && (!g_strcmp0(saved_result, "done") || !g_strcmp0(saved_result, "deferred"))) ||
             (!v2 && exact_keys(record, "schedule", keys, G_N_ELEMENTS(keys)) &&
              record_string_is(record, "schedule", "version", "1"))) &&
            page_object_name_valid(name) && !strcmp(expected, item->d_name) &&
            !g_strcmp0(saved_boot, boot) &&
            record_uint64(record, "schedule", "device", &device) && device == (uint64_t)cache.st_dev &&
            record_uint64(record, "schedule", "inode", &inode) && inode == (uint64_t)cache.st_ino &&
            record_uint64(record, "schedule", "grace", &grace) && grace == grace_us &&
            record_uint64(record, "schedule", "sequence", &seq) &&
            record_uint64(record, "schedule", "enqueued", &enqueued) && enqueued && enqueued <= now_us &&
            record_uint64(record, "schedule", "last_attempt", &attempted) && attempted <= seq &&
            record_uint64(record, "schedule", "retry_at", &retry) &&
            (retry <= now_us || retry - now_us <= RETIREMENT_BUSY_MAX_US) &&
            record_uint64(record, "schedule", "busy_count", &busy) && busy <= 7;
        if (valid && merge) {
            for (unsigned i = 0; i < merge->count; i++) {
                if (strcmp(merge->entries[i].name, name)) continue;
                merge->entries[i].enqueued = enqueued;
                merge->entries[i].last_attempt = attempted;
                merge->entries[i].retry_at = retry;
                merge->entries[i].busy_count = busy;
                merge->sequence = MAX(merge->sequence, seq);
                break;
            }
        }
        if (valid && check_page && page_results) {
            for (unsigned i = 0; i < check_page->count; i++) {
                if (!strcmp(check_page->entries[i].name, name)) {
                    page_results[i] = 3;
                    if (!check_page->committed_pending && seq <= check_page->sequence &&
                        enqueued == check_page->entries[i].enqueued &&
                        attempted == check_page->entries[i].last_attempt &&
                        retry == check_page->entries[i].retry_at &&
                        busy == check_page->entries[i].busy_count)
                        page_results[i] = 4;
                    if (inventory && size < RETIREMENT_SCHEDULE_RECORD_BYTES)
                        inventory->undersized_member = true;
                    break;
                }
            }
        }
        if (valid && check_page && v2 && !strcmp(identity, page_hex)) {
            for (unsigned i = 0; i < check_page->count; i++) {
                if (strcmp(check_page->entries[i].name, name)) continue;
                if (seq != check_page->sequence ||
                    enqueued != check_page->entries[i].enqueued) break;
                if (check_page->committed_pending &&
                    (check_page->results[i] != (!strcmp(saved_result, "done") ? 1 : 2) ||
                     check_page->entries[i].last_attempt != attempted ||
                     check_page->entries[i].retry_at != retry ||
                     check_page->entries[i].busy_count != busy)) break;
                if (!page_seen[i]) {
                    page_seen[i] = true; page_found++;
                    if (page_results) page_results[i] = !strcmp(saved_result, "done") ? 1 : 2;
                    if (page_schedule) {
                        page_schedule[i].last_attempt = attempted;
                        page_schedule[i].retry_at = retry;
                        page_schedule[i].busy_count = busy;
                    }
                }
                break;
            }
        }
        if (valid && filename && !strcmp(item->d_name, filename)) {
            found = true;
            replaced_bytes = size;
            saved_sequence = seq;
            g_strlcpy(saved.name, name, sizeof(saved.name));
            saved.enqueued = enqueued; saved.last_attempt = attempted;
            saved.retry_at = retry; saved.busy_count = busy;
            identical_result = budget && v2 && page_identity && !strcmp(identity, page_hex) &&
                seq == sequence && enqueued == entry->enqueued && attempted == entry->last_attempt &&
                retry == entry->retry_at && busy == entry->busy_count &&
                !strcmp(saved_result, kind == LATCD_RETIREMENT_RESULT_DONE ? "done" : "deferred");
            if (loading && page_identity && v2) {
                if (!strcmp(identity, page_hex)) saved_kind = !strcmp(saved_result, "done") ?
                    LATCD_RETIREMENT_RESULT_DONE : LATCD_RETIREMENT_RESULT_DEFERRED;
            }
            if (!loading) valid = (!v2 || page_identity) && sequence >= seq && entry->enqueued == enqueued &&
                entry->last_attempt >= attempted &&
                (entry->last_attempt != attempted ||
                 (entry->retry_at == retry && entry->busy_count == busy));
        }
        bytes += size;
        g_free(identity); g_free(saved_result);
        g_free(expected); g_free(name); g_free(saved_boot); g_strfreev(groups);
        g_free(raw); g_key_file_unref(record);
        if (!valid) goto out;
    }
    if (!loading && fstatat(store, filename, &path, AT_SYMLINK_NOFOLLOW) &&
        (errno != ENOENT || count >= RETIREMENT_SCHEDULE_LIMIT)) goto out;
    if (loading) {
        if (fstat(store, &after_store) || !object_stat_equal(&held_store, &after_store) ||
            !queue_watch_clean(watch) || lstat(root, &path) ||
            path.st_dev != cache.st_dev || path.st_ino != cache.st_ino ||
            !directory_matches_at(root_fd, ".gc", gc) ||
            !directory_matches_at(gc, "retirement-schedule", store)) goto out;
        if (check_page) {
            if (inventory) {
                inventory->occupied_slots = count;
                inventory->occupied_bytes = bytes;
            }
            result = page_found == check_page->count ? 0 : 1;
        } else if (loaded_kind) {
            *loaded_kind = saved_kind;
            result = saved_kind ? 0 : 1;
        } else {
            if (found && !merge) { *loaded_entry = saved; *loaded_sequence = saved_sequence; }
            result = merge || found ? 0 : 1;
        }
        goto out;
    }
    g_key_file_set_integer(output, "schedule", "version", page_identity ? 2 : 1);
    g_key_file_set_uint64(output, "schedule", "device", cache.st_dev);
    g_key_file_set_uint64(output, "schedule", "inode", cache.st_ino);
    g_key_file_set_string(output, "schedule", "boot", boot);
    g_key_file_set_uint64(output, "schedule", "grace", grace_us);
    g_key_file_set_string(output, "schedule", "name", entry->name);
    g_key_file_set_uint64(output, "schedule", "sequence", sequence);
    g_key_file_set_uint64(output, "schedule", "enqueued", entry->enqueued);
    g_key_file_set_uint64(output, "schedule", "last_attempt", entry->last_attempt);
    g_key_file_set_uint64(output, "schedule", "retry_at", entry->retry_at);
    g_key_file_set_uint64(output, "schedule", "busy_count", entry->busy_count);
    if (page_identity) {
        char hex[65];
        for (unsigned i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", page_identity[i]);
        g_key_file_set_string(output, "schedule", "page_identity", hex);
        g_key_file_set_string(output, "schedule", "result",
                              kind == LATCD_RETIREMENT_RESULT_DONE ? "done" : "deferred");
    }
    gsize output_size;
    char *data = g_key_file_to_data(output, &output_size, NULL);
    g_free(data);
    if (output_size > RETIREMENT_SCHEDULE_RECORD_BYTES - 2) goto out;
    output_size = RETIREMENT_SCHEDULE_RECORD_BYTES;
    if (output_size > RETIREMENT_SCHEDULE_BYTES - bytes ||
        bytes - replaced_bytes > RETIREMENT_SCHEDULE_BYTES - RETIREMENT_SCHEDULE_RECORD_BYTES ||
        output_size > RETIREMENT_SCHEDULE_BYTES - RETIREMENT_SCHEDULE_RECORD_BYTES -
                      (bytes - replaced_bytes) ||
        fstat(store, &after_store) || !object_stat_equal(&held_store, &after_store) ||
        !queue_watch_clean(watch) ||
        lstat(root, &path) || path.st_dev != cache.st_dev || path.st_ino != cache.st_ino ||
        !directory_matches_at(root_fd, ".gc", gc) ||
        !directory_matches_at(gc, "retirement-schedule", store)) goto out;
    if (identical_result) {
        LatcdMetadataReservation reservation;
        result = latcd_cache_capacity_page_begin(store, filename, output_size, budget, &reservation);
        if (!result) {
            latcd_cache_capacity_metadata_finish(&reservation, false, false);
            if (!latcd_cache_capacity_poll(budget->capacity)) result = -1;
        }
    } else result = write_record_kind(store, filename, output, true, true, false, budget, NULL);
out:
    g_key_file_unref(output); g_free(filename);
    if (watch >= 0) close(watch);
    if (dir) closedir(dir);
    if (store >= 0) close(store);
    if (gc >= 0) close(gc);
    if (root_fd >= 0) close(root_fd);
    return result < 0 ? fail(error, error_size, "retirement schedule store unsafe or full; reload") : result;
}

#ifdef LATCD_RETIREMENT_TESTING
int latcd_retirement_schedule_store(const char *root, const char *boot,
                                    uint64_t grace_us, uint64_t now_us, uint64_t sequence,
                                    const LatcdRetirementPageDeadline *entry,
                                    char *error, size_t error_size)
{
    if (!root) return fail(error, error_size, "invalid retirement schedule root");
    int scheduler = scheduler_lock(root, error, error_size);
    if (scheduler < 0) return -1;
    int result = retirement_schedule_access(root, boot, grace_us, now_us, sequence, entry,
                                      false, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, scheduler, error, error_size);
    close(scheduler);
    return result;
}

int latcd_retirement_schedule_store_result(const char *root, const char *boot,
                                    uint64_t grace_us, uint64_t now_us, uint64_t sequence,
                                    const LatcdRetirementPageDeadline *entry,
                                    const uint8_t page_identity[32], LatcdRetirementResultKind kind,
                                    char *error, size_t error_size)
{
    if (!root || !page_identity) return fail(error, error_size, "missing retirement page identity or root");
    int scheduler = scheduler_lock(root, error, error_size);
    if (scheduler < 0) return -1;
    int result = retirement_schedule_access(root, boot, grace_us, now_us, sequence, entry,
                                      false, NULL, NULL, NULL, page_identity, kind, NULL, NULL, NULL, NULL, NULL, NULL, NULL, scheduler, error, error_size);
    close(scheduler);
    return result;
}
#endif

int latcd_retirement_schedule_store_page_result(const char *root, uint64_t now_us,
                                    const LatcdRetirementPageState *page,
                                    const LatcdRetirementPageDeadline *entry,
                                    LatcdRetirementResultKind kind,
                                    char *error, size_t error_size)
{
    uint8_t identity[32];
    char *boot = NULL;
    uint64_t observed;
    struct stat cache;
    if (!root || !page || !entry || latcd_retirement_page_identity(page, identity) ||
        retirement_clock(&boot, &observed))
        return fail(error, error_size, "invalid retirement page result");
    bool valid = now_us <= observed &&
        !latcd_retirement_page_state_compatible(page, boot, page->grace_us, now_us) &&
        !lstat(root, &cache) && S_ISDIR(cache.st_mode) &&
        page->cache_device == (uint64_t)cache.st_dev && page->cache_inode == (uint64_t)cache.st_ino &&
        strnlen(entry->name, sizeof(entry->name)) < sizeof(entry->name);
    bool member = false;
    for (unsigned i = 0; valid && i < page->count; i++) {
        const LatcdRetirementPageDeadline *candidate = &page->entries[i];
        if (!strcmp(entry->name, candidate->name) && entry->deadline == candidate->deadline &&
            entry->enqueued == candidate->enqueued) { member = true; break; }
    }
    g_free(boot);
    if (!valid || !member) return fail(error, error_size, "retirement result is not a current page member");
    int scheduler = scheduler_lock(root, error, error_size);
    if (scheduler < 0) return -1;
    LatcdRetirementPageState persisted;
    uint8_t persisted_identity[32];
    bool legacy = false;
    if (page_state_load(root, &persisted, &legacy, error, error_size) || legacy ||
        persisted.committed_pending || persisted.budget_bound || page->committed_pending ||
        latcd_retirement_page_identity(&persisted, persisted_identity) ||
        memcmp(identity, persisted_identity, sizeof(identity)) || persisted.sequence != page->sequence) {
        close(scheduler);
        return fail(error, error_size, "retirement in-flight page changed or missing");
    }
    for (unsigned i = 0; i < persisted.count; i++) {
        if (persisted.entries[i].enqueued != page->entries[i].enqueued) {
            close(scheduler);
            return fail(error, error_size, "retirement page enqueue changed");
        }
    }
    bool persisted_member = false;
    for (unsigned i = 0; i < persisted.count; i++) {
        if (!strcmp(entry->name, persisted.entries[i].name) &&
            entry->enqueued == persisted.entries[i].enqueued) {
            persisted_member = true;
            break;
        }
    }
    if (!persisted_member) {
        close(scheduler);
        return fail(error, error_size, "retirement page enqueue changed");
    }
    int result = retirement_schedule_access(root, page->boot, page->grace_us, now_us,
                                      page->sequence, entry, false, NULL, NULL, NULL,
                                      identity, kind, NULL, NULL, page, NULL, NULL, NULL, NULL, scheduler, error, error_size);
    close(scheduler);
    return result;
}

int latcd_retirement_schedule_load_result(const char *root, const char *boot,
                                    uint64_t grace_us, uint64_t now_us, const char *name,
                                    const uint8_t page_identity[32], LatcdRetirementResultKind *kind,
                                    char *error, size_t error_size)
{
    LatcdRetirementPageDeadline query = {0};
    if (kind) *kind = 0;
    if (!kind || !page_identity || !name || strnlen(name, sizeof(query.name)) >= sizeof(query.name))
        return fail(error, error_size, "invalid retirement result lookup");
    g_strlcpy(query.name, name, sizeof(query.name));
    return retirement_schedule_access(root, boot, grace_us, now_us, 0, &query,
                                      true, NULL, NULL, NULL, page_identity, 0, kind, NULL, NULL, NULL, NULL, NULL, NULL, -1, error, error_size);
}

static int schedule_page_results(const char *root, uint64_t now_us,
                                 const LatcdRetirementPageState *page,
                                 uint8_t *results, LatcdRetirementPageInventory *inventory,
                                 char *error, size_t error_size)
{
    uint8_t identity[32];
    char *boot = NULL;
    uint64_t observed;
    if (!page || latcd_retirement_page_identity(page, identity) ||
        retirement_clock(&boot, &observed))
        return fail(error, error_size, "invalid retirement result page");
    bool compatible = now_us <= observed &&
        !latcd_retirement_page_state_compatible(page, boot, page->grace_us, now_us);
    g_free(boot);
    if (!compatible) return fail(error, error_size, "invalid retirement result page clock or boot");
    uint8_t snapshot[128] = {0};
    int result = retirement_schedule_access(root, page->boot, page->grace_us, now_us, 0, NULL,
                                      true, NULL, NULL, NULL, identity, 0, NULL, page, page, snapshot, NULL, inventory, NULL, -1,
                                      error, error_size);
    if (result >= 0 && results) memcpy(results, snapshot, sizeof(snapshot));
    return result;
}

int latcd_retirement_schedule_page_results(const char *root, uint64_t now_us,
                                    const LatcdRetirementPageState *page,
                                    uint8_t results[128], char *error, size_t error_size)
{
    if (!results) return fail(error, error_size, "missing retirement results output");
    memset(results, 0, 128);
    return schedule_page_results(root, now_us, page, results, NULL, error, error_size);
}

int latcd_retirement_page_snapshot(const char *root, uint64_t now_us,
                                    LatcdRetirementPageState *page,
                                    uint8_t results[128], LatcdRetirementPageInventory *inventory,
                                    char *error, size_t error_size)
{
    if (!root || !page || !results || !inventory) return fail(error, error_size, "invalid page snapshot output");
    memset(page, 0, sizeof(*page));
    memset(results, 0, 128);
    memset(inventory, 0, sizeof(*inventory));
    int scheduler = scheduler_lock(root, error, error_size);
    if (scheduler < 0) return -1;
    LatcdRetirementPageState persisted;
    uint8_t snapshot[128] = {0};
    LatcdRetirementPageInventory scanned = {0};
    bool legacy = false;
    int result = page_state_load(root, &persisted, &legacy, error, error_size);
    if (result || legacy || !persisted.count) {
        result = -1;
    } else {
        result = schedule_page_results(root, now_us, &persisted, snapshot, &scanned, error, error_size);
        int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        int gc = directory < 0 ? -1 : open_directory(directory, ".gc", false);
        struct stat held, path;
        if (result >= 0 && (gc < 0 || !same_directory(scheduler, gc) ||
            fstat(directory, &held) || lstat(root, &path) || held.st_dev != path.st_dev ||
            held.st_ino != path.st_ino || !directory_matches_at(directory, ".gc", gc))) result = -1;
        if (gc >= 0) close(gc);
        if (directory >= 0) close(directory);
        if (result >= 0) {
            *page = persisted;
            *inventory = scanned;
            memcpy(results, snapshot, sizeof(snapshot));
        }
    }
    close(scheduler);
    return result < 0 ? fail(error, error_size, "retirement page snapshot unsafe or missing") : result;
}

int latcd_retirement_page_budget_estimate(const LatcdRetirementPageState *page,
                                    const uint8_t results[128],
                                    const LatcdRetirementPageInventory *inventory,
                                    uint64_t *bytes)
{
    if (!bytes) { errno = EINVAL; return -1; }
    *bytes = 0;
    if (!page || !results || !inventory || latcd_retirement_page_state_valid(page) ||
        !page->count || inventory->undersized_member ||
        inventory->occupied_slots > RETIREMENT_SCHEDULE_LIMIT ||
        inventory->occupied_bytes > RETIREMENT_SCHEDULE_BYTES) {
        errno = EINVAL;
        return -1;
    }
    uint64_t missing = 0, present = 0;
    for (unsigned i = 0; i < page->count; i++) {
        if (page->committed_pending && results[i] != page->results[i]) {
            errno = EINVAL;
            return -1;
        }
        if (!results[i]) missing++;
        else if (results[i] == LATCD_RETIREMENT_RESULT_DONE ||
                 results[i] == LATCD_RETIREMENT_RESULT_DEFERRED ||
                 (!page->committed_pending && results[i] == 4)) present++;
        else { errno = EINVAL; return -1; }
    }
    if (present > inventory->occupied_slots ||
        present * RETIREMENT_SCHEDULE_RECORD_BYTES > inventory->occupied_bytes) {
        errno = EINVAL;
        return -1;
    }
    /* The schedule writer retains one record of replacement headroom. */
    if (inventory->occupied_bytes > RETIREMENT_SCHEDULE_BYTES - RETIREMENT_SCHEDULE_RECORD_BYTES ||
        missing > (RETIREMENT_SCHEDULE_BYTES - RETIREMENT_SCHEDULE_RECORD_BYTES -
                   inventory->occupied_bytes) / RETIREMENT_SCHEDULE_RECORD_BYTES) {
        errno = ENOSPC;
        return -1;
    }
    return latcd_cache_capacity_page_peak(missing,
        RETIREMENT_SCHEDULE_LIMIT - inventory->occupied_slots,
        RETIREMENT_SCHEDULE_RECORD_BYTES, RECORD_LIMIT, bytes);
}

int latcd_retirement_page_restore_budget(const char *root, LatcdCacheCapacity *capacity,
                                    uint64_t limit, uint64_t expected_grace_us, LatcdPageBudget *budget,
                                    LatcdRetirementPageState *page, char *error, size_t error_size)
{
    if (!root || !capacity || !expected_grace_us || !budget || !page)
        return fail(error, error_size, "invalid retirement budget recovery");
    memset(page, 0, sizeof(*page));
    int scheduler = scheduler_lock(root, error, error_size);
    if (scheduler < 0) return -1;
    LatcdRetirementPageState persisted;
    LatcdRetirementPageInventory inventory = {0};
    uint8_t results[128] = {0}, identity[32];
    uint64_t now = 0, bytes = 0;
    char *boot = NULL;
    bool legacy = false;
    int status = page_state_load(root, &persisted, &legacy, error, error_size);
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", false);
    struct stat held, path;
    if (status < 0 || gc < 0 || !same_directory(scheduler, gc) || fstat(directory, &held) ||
        lstat(root, &path) || held.st_dev != path.st_dev || held.st_ino != path.st_ino ||
        !directory_matches_at(directory, ".gc", gc)) status = -1;
    int matching = status < 0 ? -1 : latcd_cache_capacity_open_matching_root(capacity, root, directory);
    if (matching < 0) status = -1;
    else close(matching);
    if (!status && (legacy || !persisted.budget_bound || !persisted.count ||
        retirement_clock(&boot, &now) ||
        latcd_retirement_page_state_compatible(&persisted, boot, expected_grace_us, now) ||
        schedule_page_results(root, now, &persisted, results, &inventory, error, error_size) < 0 ||
        latcd_retirement_page_budget_identity(&persisted, identity) ||
        latcd_retirement_page_budget_estimate(&persisted, results, &inventory, &bytes) ||
        latcd_cache_capacity_restore_page(capacity, bytes, limit, identity, budget))) status = -1;
    if (!status) *page = persisted;
    g_free(boot);
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    close(scheduler);
    return status < 0 ? fail(error, error_size, "retirement budget recovery unsafe") : status;
}

#if defined(LATCD_RETIREMENT_TESTING) && defined(LATCD_CAPACITY_TESTING)
int latcd_retirement_test_page_reserve(const char *root, uint64_t now_us,
                                    LatcdCacheCapacity *capacity, uint64_t limit,
                                    LatcdPageBudget *budget, uint8_t identity[32],
                                    char *error, size_t error_size)
{
    if (!root || !capacity || !budget || !identity) return fail(error, error_size, "invalid page reservation");
    /* Do not destroy the binding of a reservation the caller still owns. */
    if (budget->capacity || budget->remaining || budget->inflight || budget->invalid) {
        errno = EBUSY;
        return fail(error, error_size, "page reservation already active");
    }
    memset(identity, 0, 32);
    int scheduler = scheduler_lock(root, error, error_size);
    if (scheduler < 0) return -1;
    LatcdRetirementPageState page;
    LatcdRetirementPageInventory inventory = {0};
    uint8_t results[128] = {0};
    bool legacy = false;
    uint8_t binding[32];
    uint64_t bytes = 0;
    int status = page_state_load(root, &page, &legacy, error, error_size);
    if (!status && !legacy && page.count)
        status = schedule_page_results(root, now_us, &page, results, &inventory, error, error_size);
    else status = -1;
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", false);
    struct stat held, path;
    if (status >= 0 && (gc < 0 || !same_directory(scheduler, gc) ||
        fstat(directory, &held) || lstat(root, &path) || held.st_dev != path.st_dev ||
        held.st_ino != path.st_ino || !directory_matches_at(directory, ".gc", gc))) status = -1;
    int capacity_root = status < 0 ? -1 :
        latcd_cache_capacity_open_matching_root(capacity, root, directory);
    if (capacity_root < 0) status = -1;
    else close(capacity_root);
    if (status >= 0 && (latcd_retirement_page_budget_identity(&page, binding) ||
        latcd_retirement_page_budget_estimate(&page, results, &inventory, &bytes) ||
        latcd_cache_capacity_test_page_reserve(capacity, bytes, limit, budget))) status = -1;
    if (status >= 0) {
        memcpy(budget->page_identity, binding, sizeof(binding));
        budget->page_identity_bound = true;
        memcpy(identity, binding, sizeof(binding));
    }
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    close(scheduler);
    return status < 0 ? fail(error, error_size, "retirement page reservation failed") : 0;
}

int latcd_retirement_test_page_budget_matches(const char *root, const uint8_t identity[32],
                                    char *error, size_t error_size)
{
    if (!root || !identity) return fail(error, error_size, "invalid page budget identity");
    int scheduler = scheduler_lock(root, error, error_size);
    if (scheduler < 0) return -1;
    LatcdRetirementPageState page;
    uint8_t actual[32];
    bool legacy = false;
    int result = page_state_load(root, &page, &legacy, error, error_size) || legacy ||
        latcd_retirement_page_budget_identity(&page, actual) || memcmp(identity, actual, 32);
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", false);
    struct stat held, path;
    if (gc < 0 || !same_directory(scheduler, gc) || fstat(directory, &held) ||
        lstat(root, &path) || held.st_dev != path.st_dev || held.st_ino != path.st_ino ||
        !directory_matches_at(directory, ".gc", gc)) result = -1;
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    close(scheduler);
    return result ? fail(error, error_size, "page budget identity changed") : 0;
}

#endif
static int page_budget_result(const char *root, uint64_t now_us,
                                    const uint8_t identity[32], LatcdPageBudget *budget,
                                    const LatcdRetirementPageDeadline *entry,
                                    LatcdRetirementResultKind kind, bool require_bound,
                                    char *error, size_t error_size)
{
    if (!root || !identity || !budget || !budget->capacity ||
        !budget->page_identity_bound || memcmp(identity, budget->page_identity, 32) || !entry ||
        strnlen(entry->name, sizeof(entry->name)) == sizeof(entry->name))
        return fail(error, error_size, "invalid budget result");
    int scheduler = scheduler_lock(root, error, error_size);
    if (scheduler < 0) return -1;
    LatcdRetirementPageState page;
    uint8_t actual[32], membership[32];
    bool legacy = false, member = false;
    int result = page_state_load(root, &page, &legacy, error, error_size) || legacy || page.committed_pending ||
        (require_bound && !page.budget_bound) ||
        latcd_retirement_page_budget_identity(&page, actual) || memcmp(identity, actual, 32) ||
        latcd_retirement_page_identity(&page, membership);
    char *boot = NULL;
    uint64_t observed = 0;
    if (!result && (retirement_clock(&boot, &observed) || now_us > observed ||
        latcd_retirement_page_state_compatible(&page, boot, page.grace_us, now_us))) result = -1;
    g_free(boot);
    for (unsigned i = 0; !result && i < page.count; i++)
        if (!strcmp(entry->name, page.entries[i].name) && entry->deadline == page.entries[i].deadline &&
            entry->enqueued == page.entries[i].enqueued) member = true;
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", false);
    int capacity_root = directory < 0 ? -1 :
        latcd_cache_capacity_open_matching_root(budget->capacity, root, directory);
    struct stat held, path;
    if (!member || gc < 0 || capacity_root < 0 || !same_directory(scheduler, gc) ||
        fstat(directory, &held) || lstat(root, &path) || held.st_dev != path.st_dev ||
        held.st_ino != path.st_ino || !directory_matches_at(directory, ".gc", gc)) result = -1;
    if (!result)
        result = retirement_schedule_access(root, page.boot, page.grace_us, now_us,
            page.sequence, entry, false, NULL, NULL, NULL, membership, kind, NULL,
            NULL, &page, NULL, NULL, NULL, budget, scheduler, error, error_size);
    if (capacity_root >= 0) close(capacity_root);
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    close(scheduler);
    return result ? fail(error, error_size, "budget result write failed") : 0;
}
int latcd_retirement_page_budget_result(const char *root, uint64_t now_us,
                                    const uint8_t identity[32], LatcdPageBudget *budget,
                                    const LatcdRetirementPageDeadline *entry,
                                    LatcdRetirementResultKind kind, char *error, size_t error_size)
{
    return page_budget_result(root, now_us, identity, budget, entry, kind, true, error, error_size);
}
#if defined(LATCD_RETIREMENT_TESTING) && defined(LATCD_CAPACITY_TESTING)
int latcd_retirement_test_budget_result(const char *root, uint64_t now_us,
                                    const uint8_t identity[32], LatcdPageBudget *budget,
                                    const LatcdRetirementPageDeadline *entry,
                                    LatcdRetirementResultKind kind, char *error, size_t error_size)
{
    return page_budget_result(root, now_us, identity, budget, entry, kind, false, error, error_size);
}
#endif

int latcd_retirement_schedule_check_page(const char *root, uint64_t now_us,
                                    const LatcdRetirementPageState *page,
                                    char *error, size_t error_size)
{
    return schedule_page_results(root, now_us, page, NULL, NULL, error, error_size);
}

static int page_commit(const char *root, uint64_t now_us,
                                    const LatcdRetirementPageState *page,
                                    LatcdPageBudget *budget, bool require_bound,
                                    char *error, size_t error_size)
{
    uint8_t expected[32], actual[32];
    if (!root || !page || latcd_retirement_page_identity(page, expected))
        return fail(error, error_size, "invalid retirement page commit");
    int scheduler = scheduler_lock(root, error, error_size);
    if (scheduler < 0) return -1;
    LatcdRetirementPageState persisted;
    bool legacy = false;
    int result = -1;
    int directory = -1, gc = -1;
    if (page_state_load(root, &persisted, &legacy, error, error_size) || legacy ||
        persisted.committed_pending || (persisted.budget_bound && !budget) ||
        (require_bound && !persisted.budget_bound) || page->committed_pending ||
        latcd_retirement_page_identity(&persisted, actual) ||
        memcmp(expected, actual, sizeof(expected)) || persisted.sequence != page->sequence) goto out;
    for (unsigned i = 0; i < persisted.count; i++)
        if (persisted.entries[i].enqueued != page->entries[i].enqueued) goto out;
    uint8_t binding[32];
    if (budget && (!budget->capacity || !budget->page_identity_bound ||
        latcd_retirement_page_budget_identity(&persisted, binding) ||
        memcmp(binding, budget->page_identity, sizeof(binding)))) goto out;
    char *boot = NULL;
    uint64_t observed;
    if (retirement_clock(&boot, &observed)) goto out;
    bool compatible = now_us <= observed &&
        !latcd_retirement_page_state_compatible(&persisted, boot, persisted.grace_us, now_us);
    g_free(boot);
    if (!compatible || retirement_schedule_access(root, persisted.boot, persisted.grace_us,
        now_us, 0, NULL, true, NULL, NULL, NULL, actual, 0, NULL, &persisted,
        &persisted, persisted.results, persisted.entries, NULL, NULL, -1, error, error_size)) goto out;
    directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    gc = directory < 0 ? -1 : open_directory(directory, ".gc", false);
    struct stat held, path;
    if (!same_directory(scheduler, gc) || fstat(directory, &held) || lstat(root, &path) ||
        held.st_dev != path.st_dev || held.st_ino != path.st_ino ||
        !directory_matches_at(directory, ".gc", gc)) goto out;
    persisted.committed_pending = true;
    if (budget) {
        int matching = latcd_cache_capacity_open_matching_root(budget->capacity, root, directory);
        if (matching < 0) goto out;
        close(matching);
    }
    result = page_state_store_fd(directory, gc, &persisted, budget, NULL);
out:
    int saved = errno;
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    close(scheduler);
    errno = saved;
    return result ? fail(error, error_size, "retirement page commit failed; reload") : 0;
}

int latcd_retirement_page_commit(const char *root, uint64_t now_us,
                                    const LatcdRetirementPageState *page,
                                    char *error, size_t error_size)
{
    return page_commit(root, now_us, page, NULL, false, error, error_size);
}

int latcd_retirement_page_budget_commit(const char *root, uint64_t now_us,
                                    const LatcdRetirementPageState *page, LatcdPageBudget *budget,
                                    char *error, size_t error_size)
{
    if (!budget || !page)
        return fail(error, error_size, "missing bound page budget");
    return page_commit(root, now_us, page, budget, true, error, error_size);
}

int latcd_retirement_page_finish_preserving_results(const char *root, uint64_t now_us,
                                          LatcdPageBudget *budget, char *error, size_t error_size)
{
    if (!root || !budget || !budget->capacity || !budget->page_identity_bound)
        return fail(error, error_size, "invalid deferred page completion");
    int scheduler = scheduler_lock(root, error, error_size);
    if (scheduler < 0) return -1;
    LatcdRetirementPageState page;
    bool legacy = false;
    uint8_t identity[32], results[128] = {0};
    LatcdRetirementPageInventory inventory = {0};
    uint64_t required;
    int result = -1, directory = -1, gc = -1, matching = -1;
    struct stat held, path;
    if (page_state_load(root, &page, &legacy, error, error_size) || legacy ||
        !page.budget_bound || !page.committed_pending ||
        latcd_retirement_page_budget_identity(&page, identity) ||
        memcmp(identity, budget->page_identity, sizeof(identity))) goto out;
    if (schedule_page_results(root, now_us, &page, results, &inventory, error, error_size) ||
        latcd_retirement_page_budget_estimate(&page, results, &inventory, &required)) goto out;
    directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    gc = directory < 0 ? -1 : open_directory(directory, ".gc", false);
    if (gc < 0 || !same_directory(scheduler, gc) || fstat(directory, &held) ||
        lstat(root, &path) || held.st_dev != path.st_dev || held.st_ino != path.st_ino ||
        !directory_matches_at(directory, ".gc", gc)) goto out;
    matching = latcd_cache_capacity_open_matching_root(budget->capacity, root, directory);
    if (matching < 0) goto out;
    g_strlcpy(page.committed_cursor, page.cursor, sizeof(page.committed_cursor));
    page.cursor[0] = 0;
    page.count = 0;
    page.committed_pending = false;
    page.budget_bound = false;
    if (page_state_store_fd(directory, gc, &page, budget, NULL)) goto out;
#if defined(LATCD_RETIREMENT_TESTING) && defined(LATCD_CAPACITY_TESTING)
    if (latcd_retirement_test_before_page_finish) latcd_retirement_test_before_page_finish(budget);
#endif
    result = latcd_cache_capacity_finish_page(budget->capacity, budget);
out:
    if (matching >= 0) close(matching);
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    close(scheduler);
    return result ? fail(error, error_size, "page completion uncertain; reload") : 0;
}

#if defined(LATCD_RETIREMENT_TESTING) && defined(LATCD_CAPACITY_TESTING)
int latcd_retirement_test_budget_commit(const char *root, uint64_t now_us,
                                    const LatcdRetirementPageState *page, LatcdPageBudget *budget,
                                    char *error, size_t error_size)
{
    if (!budget) return fail(error, error_size, "missing page budget");
    return page_commit(root, now_us, page, budget, false, error, error_size);
}
#endif

int latcd_retirement_schedule_load(const char *root, const char *boot,
                                   uint64_t grace_us, uint64_t now_us, const char *name,
                                   uint64_t *sequence, LatcdRetirementPageDeadline *entry,
                                   char *error, size_t error_size)
{
    LatcdRetirementPageDeadline query = {0};
    bool valid = entry && sequence && name &&
        strnlen(name, sizeof(query.name)) < sizeof(query.name);
    if (valid) g_strlcpy(query.name, name, sizeof(query.name));
    if (entry) memset(entry, 0, sizeof(*entry));
    if (sequence) *sequence = 0;
    if (!valid) return fail(error, error_size, "invalid retirement schedule lookup");
    return retirement_schedule_access(root, boot, grace_us, now_us, 0, &query,
                                      true, sequence, entry, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, -1, error, error_size);
}

int latcd_retirement_schedule_merge_page(const char *root, const char *boot,
                                         uint64_t grace_us, uint64_t now_us,
                                         LatcdRetirementPageState *page,
                                         char *error, size_t error_size)
{
    if (!page || page->count > 128)
        return fail(error, error_size, "invalid retirement schedule page");
    LatcdRetirementPageState next = *page;
    for (unsigned i = 0; i < next.count; i++) {
        if (strnlen(next.entries[i].name, sizeof(next.entries[i].name)) == sizeof(next.entries[i].name) ||
            !page_object_name_valid(next.entries[i].name) ||
            !next.entries[i].deadline || !next.entries[i].enqueued ||
            (i && strcmp(next.entries[i - 1].name, next.entries[i].name) >= 0))
            return fail(error, error_size, "invalid retirement schedule page");
    }
    if (retirement_schedule_access(root, boot, grace_us, now_us, 0, NULL,
                                   true, NULL, NULL, &next, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, -1, error, error_size)) return -1;
    *page = next;
    return 0;
}

int latcd_retirement_page_plan(const char *const *names, size_t count,
                               const char *after, const LatcdRetirementPageDeadline *schedule,
                               size_t schedule_count, LatcdRetirementPageState *state)
{
    LatcdRetirementPage page;
    if (!state) return -1;
    memset(state, 0, sizeof(*state));
    if (!names || (!schedule && schedule_count) ||
        latcd_retirement_page_select(names, count, after, &page) < 0) return -1;
    if (!page.count) return 0;
    unsigned copied = 0;
    for (size_t i = 0; i < count && copied < page.count; i++) {
        if (after && strcmp(names[i], after) <= 0) continue;
        bool found = false;
        for (size_t j = 0; j < schedule_count; j++) {
            if (strcmp(names[i], schedule[j].name)) continue;
            state->entries[state->count++] = schedule[j];
            found = true;
            copied++;
            for (size_t k = j + 1; k < schedule_count; k++) {
                if (!strcmp(names[i], schedule[k].name)) {
                    memset(state, 0, sizeof(*state));
                    return -1;
                }
            }
            break;
        }
        if (!found) {
            memset(state, 0, sizeof(*state));
            return -1;
        }
    }
    if (!state->count) return 0;
    g_strlcpy(state->cursor, state->entries[state->count - 1].name, sizeof(state->cursor));
    return 1;
}

static int set_clock(GKeyFile *record, const char *prefix)
{
    char *boot = NULL;
    uint64_t stamp;
    if (retirement_clock(&boot, &stamp)) return -1;
    char *boot_key = g_strdup_printf("%s_boot", prefix);
    char *time_key = g_strdup_printf("%s_boottime_us", prefix);
    g_key_file_set_string(record, "transaction", boot_key, boot);
    g_key_file_set_uint64(record, "transaction", time_key, stamp);
    g_free(boot);
    g_free(boot_key);
    g_free(time_key);
    return 0;
}

static int retirement_prepare(int root_fd, const char *source,
                            const char *next, size_t next_size, const char *objects,
                            char **transaction, char *error, size_t error_size)
{
    *transaction = NULL;
    if (!source_valid(source) || !next || !next_size || next_size > MANIFEST_LIMIT)
        return fail(error, error_size, "invalid retirement transaction input");
    int store = open_store(root_fd, true);
    int result = -1;
    char *previous = NULL;
    size_t previous_size = 0;
    char *current = g_strdup_printf("%s.current", source);
    if (store < 0 || read_file(root_fd, current, MANIFEST_LIMIT,
                              &previous, &previous_size) < 0) goto out;
    GKeyFile *record = g_key_file_new();
    char *old64 = g_base64_encode((guchar *)previous, previous_size);
    char *new64 = g_base64_encode((const guchar *)next, next_size);
    g_key_file_set_integer(record, "transaction", "version", 2);
    char *object64 = g_base64_encode((const guchar *)(objects ? objects : ""),
                                    objects ? strlen(objects) : 0);
    g_key_file_set_string(record, "transaction", "objects", object64);
    g_free(object64);
    g_key_file_set_string(record, "transaction", "source", source);
    g_key_file_set_string(record, "transaction", "state", "PREPARED");
    g_key_file_set_string(record, "transaction", "previous", old64);
    g_key_file_set_string(record, "transaction", "next", new64);
    int clock_status = set_clock(record, "prepared");
    gsize prepared_size = 0;
    char *prepared_data = g_key_file_to_data(record, &prepared_size, NULL);
    g_free(prepared_data);
    char *uuid = g_uuid_string_random();
    char *name = g_strdup_printf("%s.ini", uuid);
    g_free(uuid);
    if (prepared_size > RECORD_LIMIT - PREPARED_COMPLETION_HEADROOM) errno = EFBIG;
    result = clock_status || prepared_size > RECORD_LIMIT - PREPARED_COMPLETION_HEADROOM ?
        -1 : write_record(store, name, record);
    if (!result) *transaction = g_strdup(name);
    g_free(name);
    g_free(old64);
    g_free(new64);
    g_key_file_unref(record);
out:
    if (result) fail(error, error_size, "cannot persist retirement PREPARED: %s", strerror(errno));
    if (store >= 0) close(store);
    g_free(current);
    g_free(previous);
    return result;
}

static bool name_valid(const char *name)
{
    if (!name || strlen(name) != 40 || strcmp(name + 36, ".ini")) return false;
    char uuid[37];
    memcpy(uuid, name, 36);
    uuid[36] = 0;
    return g_uuid_string_is_valid(uuid);
}

static bool record_shape_valid(GKeyFile *record)
{
    gsize count;
    char **groups = g_key_file_get_groups(record, &count);
    bool valid = count == 1 && !strcmp(groups[0], "transaction");
    g_strfreev(groups);
    char **keys = g_key_file_get_keys(record, "transaction", &count, NULL);
    GHashTable *seen = g_hash_table_new(g_str_hash, g_str_equal);
    const char *allowed[] = { "version", "source", "state", "previous", "next",
        "prepared_boot", "prepared_boottime_us", "retired_boot", "retired_boottime_us",
        "objects", "objects_status", "binding_status", "retirement_clock_reason" };
    for (gsize i = 0; valid && i < count; i++) {
        bool known = false;
        for (size_t j = 0; j < G_N_ELEMENTS(allowed); j++)
            known |= !strcmp(keys[i], allowed[j]);
        valid = known && g_hash_table_add(seen, keys[i]);
    }
    g_hash_table_unref(seen);
    g_strfreev(keys);
    if (g_key_file_has_key(record, "transaction", "retirement_clock_reason", NULL)) {
        char *reason = g_key_file_get_string(record, "transaction", "retirement_clock_reason", NULL);
        valid = valid && (!g_strcmp0(reason, "BOOT_CHANGED") || !g_strcmp0(reason, "CLOCK_MISSING"));
        g_free(reason);
    }
    return valid;
}

static guchar *decode_snapshot(const char *value, gsize *size)
{
    guchar *decoded = g_base64_decode(value, size);
    char *canonical = g_base64_encode(decoded, *size);
    bool valid = *size <= MANIFEST_LIMIT && !strcmp(value, canonical);
    g_free(canonical);
    if (!valid) { g_free(decoded); return NULL; }
    return decoded;
}

static bool exact_keys(GKeyFile *record, const char *group,
                        const char *const *required, size_t required_count)
{
    gsize count;
    char **keys = g_key_file_get_keys(record, group, &count, NULL);
    bool valid = keys && count == required_count;
    for (size_t i = 0; valid && i < required_count; i++) {
        unsigned matches = 0;
        for (gsize j = 0; j < count; j++) matches += !strcmp(keys[j], required[i]);
        valid = matches == 1;
    }
    g_strfreev(keys);
    return valid;
}

static bool digest_valid(const char *value)
{
    return value && strlen(value) == 64 && strspn(value, "0123456789abcdef") == 64;
}

static bool manifest_references(const char *source, const char *raw, size_t size,
                                GHashTable *expected)
{
    if (!raw || !size || size >= MANIFEST_LIMIT || memchr(raw, 0, size)) return false;
    char *text = g_strndup(raw, size);
    JSON_Value *value = json_parse_string(text);
    JSON_Object *manifest = json_value_get_object(value);
    const char *required[] = {"version", "module", "native", "tbset",
        "source_sha256", "codegen_id", "published_sequence"};
    const char *optional[] = {"module_sha256", "native_sha256"};
    bool valid = manifest != NULL;
    for (size_t i = 0; valid && i < json_object_get_count(manifest); i++) {
        const char *key = json_object_get_name(manifest, i);
        bool known = false;
        for (size_t j = 0; j < G_N_ELEMENTS(required); j++) known |= !strcmp(key, required[j]);
        for (size_t j = 0; j < G_N_ELEMENTS(optional); j++) known |= !strcmp(key, optional[j]);
        valid = known;
    }
    for (size_t i = 0; valid && i < G_N_ELEMENTS(required); i++)
        valid = json_object_has_value(manifest, required[i]);
    const char *version = lat_json_number_token(json_object_get_value(manifest, "version"));
    const char *sequence = lat_json_number_token(json_object_get_value(manifest, "published_sequence"));
    const char *identity = json_object_get_string(manifest, "source_sha256");
    const char *codegen = json_object_get_string(manifest, "codegen_id");
    char *end = NULL;
    errno = 0;
    if (sequence) (void)g_ascii_strtoull(sequence, &end, 10);
    valid = valid && version && !strcmp(version, "2") && sequence && *sequence &&
        strspn(sequence, "0123456789") == strlen(sequence) && end && !*end && !errno &&
        identity && !strcmp(identity, source) && digest_valid(codegen);
    valid = valid && identity && codegen &&
        json_object_get_string_len(manifest, "source_sha256") == strlen(identity) &&
        json_object_get_string_len(manifest, "codegen_id") == strlen(codegen);
    for (size_t i = 0; valid && i < G_N_ELEMENTS(optional); i++) {
        if (json_object_has_value(manifest, optional[i])) {
            const char *hash = json_object_get_string(manifest, optional[i]);
            valid = digest_valid(hash) && json_object_get_string_len(manifest, optional[i]) == strlen(hash);
        }
    }
    const char *roles[] = {"module", "native", "tbset"};
    const char *suffixes[] = {".so", ".native", ".tbset"};
    for (size_t i = 0; valid && i < G_N_ELEMENTS(roles); i++) {
        const char *name = json_object_get_string(manifest, roles[i]);
        valid = name && json_object_get_string_len(manifest, roles[i]) == strlen(name);
        if (!valid || (i == 2 && !*name)) continue;
        valid = object_name_valid(source, name) && g_str_has_suffix(name, suffixes[i]);
        if (!valid) break;
        const char *hash = i < 2 ? json_object_get_string(manifest, optional[i]) : NULL;
        const char *prior = g_hash_table_lookup(expected, name);
        if (prior && *prior && hash && strcmp(prior, hash)) { valid = false; break; }
        if (!prior || !*prior)
            g_hash_table_replace(expected, g_strdup(name), g_strdup(hash ? hash : ""));
    }
    json_value_free(value);
    g_free(text);
    return valid;
}

/* Caller holds the reference roots EX latch under the owner contract. This bounded final
 * check is defense in depth, not a persistent reference index or domain gate. */
static int object_current_status(int root, const char *name)
{
    int copy = openat(root, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *directory = copy < 0 ? NULL : fdopendir(copy);
    if (!directory) { if (copy >= 0) close(copy); return -1; }
    struct stat before = {0}, after;
    int result = fstat(root, &before) ? -1 : 0;
    unsigned visited = 0;
    int64_t started = g_get_monotonic_time();
    while (!result) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (++visited > 4096 || g_get_monotonic_time() - started >= 10000) { result = -1; break; }
        if (!g_str_has_suffix(entry->d_name, ".current")) continue;
        char source[65] = {0};
        if (strlen(entry->d_name) == 72) memcpy(source, entry->d_name, 64);
        char *raw = NULL;
        size_t size;
        GHashTable *refs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        bool valid = source_valid(source) &&
            !read_file(root, entry->d_name, MANIFEST_LIMIT, &raw, &size) &&
            manifest_references(source, raw, size, refs);
        result = !valid ? -1 : g_hash_table_contains(refs, name) ? 1 : 0;
        g_hash_table_unref(refs);
        g_free(raw);
    }
    if (fstat(root, &after) || !object_stat_equal(&before, &after)) result = -1;
    closedir(directory);
    return result;
}

int latcd_retirement_validate_binding(const char *source,
                                      const char *previous, size_t previous_size,
                                      const char *next, size_t next_size,
                                      const char *raw, size_t size)
{
    if (!source_valid(source) || !raw || !size || size >= 16384 || memchr(raw, 0, size)) return -1;
    GHashTable *expected = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    GHashTable *observed = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    bool valid = (!previous_size || manifest_references(source, previous, previous_size, expected)) &&
        manifest_references(source, next, next_size, expected);
    GKeyFile *objects = g_key_file_new();
    valid = valid && g_key_file_load_from_data(objects, raw, size, 0, NULL);
    int count = g_key_file_get_integer(objects, "objects", "count", NULL);
    const char *header[] = {"count"};
    const char *object_fields[] = {"name", "device", "inode", "size", "allocated", "sha256"};
    gsize group_count;
    char **groups = g_key_file_get_groups(objects, &group_count);
    valid = valid && count > 0 && count <= 6 && group_count == (gsize)count + 1 &&
        exact_keys(objects, "objects", header, G_N_ELEMENTS(header));
    g_strfreev(groups);
    for (int i = 0; valid && i < count; i++) {
        char group[32];
        snprintf(group, sizeof(group), "object%d", i);
        if (!exact_keys(objects, group, object_fields, G_N_ELEMENTS(object_fields))) { valid = false; break; }
        char *name = g_key_file_get_string(objects, group, "name", NULL);
        char *hash = g_key_file_get_string(objects, group, "sha256", NULL);
        const char *required_hash = name ? g_hash_table_lookup(expected, name) : NULL;
        valid = required_hash && digest_valid(hash) && (!*required_hash || !strcmp(required_hash, hash));
        if (valid) {
            /* Repeated names occur when consecutive manifests share an object.
             * All identity fields must agree, not merely the filename/hash. */
            const char *fields[] = {"device", "inode", "size", "allocated", "sha256"};
            GString *signature = g_string_new(NULL);
            for (size_t j = 0; valid && j < G_N_ELEMENTS(fields); j++) {
                char *field = g_key_file_get_string(objects, group, fields[j], NULL);
                valid = field && !strchr(field, '\n');
                if (valid && j < 4) {
                    char *end;
                    errno = 0;
                    (void)g_ascii_strtoull(field, &end, 10);
                    valid = *field && strspn(field, "0123456789") == strlen(field) && !*end && !errno;
                }
                if (valid) g_string_append_printf(signature, "%s\n", field);
                g_free(field);
            }
            const char *prior = g_hash_table_lookup(observed, name);
            valid = valid && (!prior || !strcmp(prior, signature->str));
            if (valid) g_hash_table_replace(observed, g_strdup(name), g_strdup(signature->str));
            g_string_free(signature, TRUE);
        }
        g_free(name);
        g_free(hash);
    }
    valid = valid && g_hash_table_size(expected) == g_hash_table_size(observed);
    g_hash_table_unref(expected);
    g_hash_table_unref(observed);
    g_key_file_unref(objects);
    return valid ? 0 : -1;
}

static bool hold_id_valid(const char *id)
{
    return id && strlen(id) == 36 && g_uuid_string_is_valid(id);
}

static bool hold_record_valid(GKeyFile *record, const char *id, const char *name,
                               const struct stat *cache, const struct stat *object)
{
    const char *fields[] = {"version", "id", "name", "reason", "state",
        "cache_device", "cache_inode", "object_device", "object_inode"};
    gsize count;
    char **groups = g_key_file_get_groups(record, &count);
    bool valid = count == 1 && !strcmp(groups[0], "hold") &&
        exact_keys(record, "hold", fields, G_N_ELEMENTS(fields));
    g_strfreev(groups);
    const char *keys[] = {"version", "id", "name"};
    const char *expected[] = {"1", id, name};
    for (unsigned i = 0; valid && i < G_N_ELEMENTS(keys); i++) {
        char *value = g_key_file_get_string(record, "hold", keys[i], NULL);
        valid = !g_strcmp0(value, expected[i]);
        g_free(value);
    }
    char *reason = g_key_file_get_string(record, "hold", "reason", NULL);
    char *state = g_key_file_get_string(record, "hold", "state", NULL);
    valid &= (!g_strcmp0(reason, "ROLLBACK") || !g_strcmp0(reason, "MIGRATION") ||
              !g_strcmp0(reason, "EXTERNAL")) &&
             (!g_strcmp0(state, "ACTIVE") || !g_strcmp0(state, "RELEASED"));
    g_free(reason); g_free(state);
    uint64_t numbers[] = {cache->st_dev, cache->st_ino, object->st_dev, object->st_ino};
    for (unsigned i = 0; valid && i < G_N_ELEMENTS(numbers); i++) {
        char *value = g_key_file_get_string(record, "hold", fields[5 + i], NULL);
        errno = 0;
        char *end = NULL;
        uint64_t number = value ? g_ascii_strtoull(value, &end, 10) : 0;
        valid = value && *value && strspn(value, "0123456789") == strlen(value) &&
            !errno && end && !*end && number == numbers[i];
        g_free(value);
    }
    return valid;
}

typedef struct MountLeaseRecord {
    char *scope;
    char *source;
    char *name;
    char *state;
    uint64_t object_device;
    uint64_t object_inode;
} MountLeaseRecord;

static void mount_lease_clear(MountLeaseRecord *lease)
{
    g_free(lease->scope);
    g_free(lease->source);
    g_free(lease->name);
    g_free(lease->state);
    memset(lease, 0, sizeof(*lease));
}

static bool mount_lease_parse(GKeyFile *record, const char *id,
                              const struct stat *cache, MountLeaseRecord *lease)
{
    const char *fields[] = {"version", "id", "scope", "state", "cache_device",
        "cache_inode", "source", "name", "object_device", "object_inode"};
    gsize groups = 0;
    char **names = g_key_file_get_groups(record, &groups);
    bool valid = groups == 1 && !strcmp(names[0], "mount") &&
        exact_keys(record, "mount", fields, G_N_ELEMENTS(fields));
    g_strfreev(names);
    valid = valid && record_string_is(record, "mount", "version", "1") &&
        record_string_is(record, "mount", "id", id);
    uint64_t cache_device, cache_inode;
    valid = valid &&
        record_uint64(record, "mount", "cache_device", &cache_device) &&
        cache_device == (uint64_t)cache->st_dev &&
        record_uint64(record, "mount", "cache_inode", &cache_inode) &&
        cache_inode == (uint64_t)cache->st_ino;
    lease->scope = g_key_file_get_string(record, "mount", "scope", NULL);
    lease->source = g_key_file_get_string(record, "mount", "source", NULL);
    lease->name = g_key_file_get_string(record, "mount", "name", NULL);
    lease->state = g_key_file_get_string(record, "mount", "state", NULL);
    valid = valid && lease->scope && lease->source && lease->name && lease->state &&
        (!strcmp(lease->state, "ACTIVE") || !strcmp(lease->state, "RELEASED")) &&
        record_uint64(record, "mount", "object_device", &lease->object_device) &&
        record_uint64(record, "mount", "object_inode", &lease->object_inode);
    if (!valid) {
        mount_lease_clear(lease);
        return false;
    }
    if (!strcmp(lease->scope, "CACHE")) {
        valid = valid && !*lease->source && !*lease->name &&
            !lease->object_device && !lease->object_inode;
    } else if (!strcmp(lease->scope, "SOURCE")) {
        valid = valid && source_valid(lease->source) && !*lease->name &&
            !lease->object_device && !lease->object_inode;
    } else if (!strcmp(lease->scope, "OBJECT")) {
        valid = valid && source_valid(lease->source) &&
            object_name_valid(lease->source, lease->name) &&
            lease->object_device && lease->object_inode;
    } else valid = false;
    if (!valid) mount_lease_clear(lease);
    return valid;
}

/* Called with retirement roots EX (or while a participant still holds SH).
 * One malformed or excessive record freezes the object. */
static int mount_lease_status(int root, int gc, const char *source,
                              const char *name, const struct stat *object)
{
    int store = open_directory(gc, "mount-leases", false);
    int saved = errno;
    if (store < 0) return saved == ENOENT ? 0 : -1;
    struct stat cache;
    if (fstat(root, &cache)) { close(store); return -1; }
    DIR *directory = fdopendir(store);
    if (!directory) { close(store); return -1; }
    int result = 0;
    unsigned visited = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (++visited > 128 || strlen(entry->d_name) != 40 ||
            strcmp(entry->d_name + 36, ".ini")) { result = -1; break; }
        char id[37];
        memcpy(id, entry->d_name, 36);
        id[36] = 0;
        char *raw = NULL;
        size_t size;
        GKeyFile *record = g_key_file_new();
        MountLeaseRecord lease = {0};
        bool valid = hold_id_valid(id) &&
            !read_file(dirfd(directory), entry->d_name, MANIFEST_LIMIT, &raw, &size) &&
            !memchr(raw, 0, size) &&
            g_key_file_load_from_data(record, raw, size, 0, NULL) &&
            mount_lease_parse(record, id, &cache, &lease);
        if (!valid) result = -1;
        else if (!strcmp(lease.state, "ACTIVE")) {
            if (!strcmp(lease.scope, "CACHE")) result = 1;
            else if (!strcmp(lease.scope, "SOURCE") && !strcmp(lease.source, source))
                result = 1;
            else if (!strcmp(lease.scope, "OBJECT") && !strcmp(lease.source, source) &&
                     !strcmp(lease.name, name)) {
                if (lease.object_device != (uint64_t)object->st_dev ||
                    lease.object_inode != (uint64_t)object->st_ino) result = -1;
                else result = 1;
            }
        }
        mount_lease_clear(&lease);
        g_free(raw);
        g_key_file_unref(record);
        if (result) break;
    }
    closedir(directory);
    return result;
}

/* Called under source EX. Any unreadable or partial hold freezes the object.
 * Bounded work: overflow retains rather than doing a long scan under S. */
static int object_hold_status(int root, const char *name, const struct stat *object)
{
    int gc = open_directory(root, ".gc", false);
    if (gc < 0) return errno == ENOENT ? 0 : -1;
    int holds = open_directory(gc, "holds", false);
    int saved = errno;
    close(gc);
    if (holds < 0) return saved == ENOENT ? 0 : -1;
    int fd = open_directory(holds, name, false);
    saved = errno;
    close(holds);
    if (fd < 0) return saved == ENOENT ? 0 : -1;
    DIR *directory = fdopendir(fd);
    if (!directory) { close(fd); return -1; }
    struct stat cache;
    int result = fstat(root, &cache) ? -1 : 0;
    unsigned visited = 0;
    while (!result) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char *raw = NULL;
        size_t size;
        if (++visited > 128 || !name_valid(entry->d_name) ||
            read_file(fd, entry->d_name, MANIFEST_LIMIT, &raw, &size)) { result = -1; break; }
        char id[37];
        memcpy(id, entry->d_name, 36); id[36] = 0;
        GKeyFile *record = g_key_file_new();
        bool valid = !memchr(raw, 0, size) &&
            g_key_file_load_from_data(record, raw, size, 0, NULL) &&
            hold_record_valid(record, id, name, &cache, object);
        char *state = g_key_file_get_string(record, "hold", "state", NULL);
        result = !valid ? -1 : !g_strcmp0(state, "ACTIVE") ? 1 : 0;
        g_free(state); g_free(raw); g_key_file_unref(record);
    }
    closedir(directory);
    return result;
}

static bool record_string_is(GKeyFile *record, const char *group,
                              const char *key, const char *expected)
{
    char *value = g_key_file_get_string(record, group, key, NULL);
    bool equal = !g_strcmp0(value, expected);
    g_free(value);
    return equal;
}

static bool record_uint64(GKeyFile *record, const char *group, const char *key,
                           uint64_t *number)
{
    char *value = g_key_file_get_string(record, group, key, NULL), *end = NULL;
    errno = 0;
    *number = value ? g_ascii_strtoull(value, &end, 10) : 0;
    bool valid = value && *value && strspn(value, "0123456789") == strlen(value) &&
        !errno && end && !*end;
    g_free(value);
    return valid;
}

int latcd_cache_domain_validate(const char *root, char id[37],
                                char *error, size_t error_size)
{
    return lat_aot_v2_cache_domain_validate(root, id, error, error_size);
}

int latcd_cache_domain_init(const char *root, char id[37],
                            char *error, size_t error_size)
{
    if (!root || !*root || !id) return fail(error, error_size, "invalid cache domain root");
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return fail(error, error_size, "cannot open cache domain root");
    struct stat cache, lock_status;
    int gc = -1, lock = -1, result = -1;
    if (fstat(directory, &cache) || !S_ISDIR(cache.st_mode) ||
        cache.st_uid != geteuid() || (cache.st_mode & 0077)) goto out;
    gc = open_directory(directory, ".gc", true);
    if (gc < 0) goto out;
    lock = openat(gc, "domain.lock",
                  O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    bool created = lock >= 0;
    if (lock < 0 && errno == EEXIST)
        lock = openat(gc, "domain.lock", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (lock < 0 || (created && fchmod(lock, 0600)) ||
        flock(lock, LOCK_EX | LOCK_NB) ||
        fstat(lock, &lock_status) || !S_ISREG(lock_status.st_mode) ||
        lock_status.st_uid != geteuid() || lock_status.st_nlink != 1 ||
        (lock_status.st_mode & 0077) || lock_status.st_size) goto out;
    struct stat marker_status;
    if (!fstatat(gc, "domain.ini", &marker_status, AT_SYMLINK_NOFOLLOW)) {
        if (lat_aot_v2_cache_domain_validate(
                root, id, error, error_size) != 1) {
            goto out;
        }
        result = 0;
        goto out;
    }
    if (errno != ENOENT) goto out;
    char *new_id = g_uuid_string_random();
    char *boot = NULL;
    uint64_t now_us;
    if (!new_id || retirement_clock(&boot, &now_us)) {
        g_free(new_id);
        g_free(boot);
        goto out;
    }
    GKeyFile *record = g_key_file_new();
    g_key_file_set_integer(record, "domain", "version", 1);
    g_key_file_set_string(record, "domain", "id", new_id);
    g_key_file_set_uint64(record, "domain", "cache_device", cache.st_dev);
    g_key_file_set_uint64(record, "domain", "cache_inode", cache.st_ino);
    g_key_file_set_uint64(record, "domain", "lock_device", lock_status.st_dev);
    g_key_file_set_uint64(record, "domain", "lock_inode", lock_status.st_ino);
    g_key_file_set_string(record, "domain", "created_boot", boot);
    g_key_file_set_uint64(record, "domain", "created_boottime_us", now_us);
    if (!hold_id_valid(boot) || write_record(gc, "domain.ini", record)) {
        g_key_file_unref(record);
        g_free(new_id);
        g_free(boot);
        goto out;
    }
    g_key_file_unref(record);
    g_free(new_id);
    g_free(boot);
    if (lat_aot_v2_cache_domain_validate(root, id, error, error_size) != 1) {
        goto out;
    }
    result = 0;
out:
    if (lock >= 0) close(lock);
    if (gc >= 0) close(gc);
    close(directory);
    if (result) return fail(error, error_size,
        "cache domain initialization rejected or incomplete");
    return 0;
}

static bool task_identity_valid(GKeyFile *record, const char *group)
{
    const char *numbers[] = {"device", "inode", "size", "mode", "uid", "mtime_nsec"};
    uint64_t value;
    for (unsigned i = 0; i < G_N_ELEMENTS(numbers); i++) {
        if (!record_uint64(record, group, numbers[i], &value) ||
            (i == 5 && value >= 1000000000)) return false;
    }
    char *seconds = g_key_file_get_string(record, group, "mtime_sec", NULL), *end = NULL;
    const char *digits = seconds && *seconds == '-' ? seconds + 1 : seconds;
    errno = 0;
    if (seconds) (void)g_ascii_strtoll(seconds, &end, 10);
    bool valid = digits && *digits && strspn(digits, "0123456789") == strlen(digits) &&
        !errno && end && !*end;
    g_free(seconds);
    return valid;
}

/* A release receipt is effective only with an exact task inode and no holder.
 * Missing receipt is a hold, not evidence of task completion. */
static int task_inputs_released(int gc, const char *name, bool copying,
                                 int task, const struct stat *identity)
{
    int releases = open_directory(gc, copying ? "copy-releases" : "compiler-releases", false);
    if (releases < 0) return errno == ENOENT ? 0 : -1;
    char *raw = NULL;
    size_t size;
    int status = read_file(releases, name, MANIFEST_LIMIT, &raw, &size);
    close(releases);
    if (status) return status == 1 ? 0 : -1;
    GKeyFile *record = g_key_file_new();
    const char *keys[] = {"version", "task_id", "state", "task_device", "task_inode"};
    gsize count;
    char id[37];
    memcpy(id, name, 36); id[36] = 0;
    bool valid = !memchr(raw, 0, size) && g_key_file_load_from_data(record, raw, size, 0, NULL);
    char **groups = g_key_file_get_groups(record, &count);
    uint64_t device, inode;
    valid = valid && count == 1 && !strcmp(groups[0], "handoff") &&
        exact_keys(record, "handoff", keys, G_N_ELEMENTS(keys)) &&
        record_string_is(record, "handoff", "version", "1") &&
        record_string_is(record, "handoff", "task_id", id) &&
        record_string_is(record, "handoff", "state", copying ? "RELEASED" : "INPUTS_RELEASED") &&
        record_uint64(record, "handoff", "task_device", &device) && device == (uint64_t)identity->st_dev &&
        record_uint64(record, "handoff", "task_inode", &inode) && inode == (uint64_t)identity->st_ino;
    g_strfreev(groups); g_free(raw); g_key_file_unref(record);
    if (!valid) return -1;
    if (flock(task, LOCK_EX | LOCK_NB)) return errno == EWOULDBLOCK ? 0 : -1;
    return 1;
}

/* Defense in depth, not the full reference graph. The management owner must
 * serialize local publisher transitions. No unbounded task walk under S. */
static int object_task_status(int root, const char *name, const struct stat *object)
{
    int gc = open_directory(root, ".gc", false);
    if (gc < 0) return errno == ENOENT ? 0 : -1;
    int tasks = open_directory(gc, "tasks", false);
    if (tasks < 0) { int result = errno == ENOENT ? 0 : -1; close(gc); return result; }
    DIR *directory = fdopendir(tasks);
    if (!directory) { close(tasks); close(gc); return -1; }
    struct stat cache;
    int result = fstat(root, &cache) ? -1 : 0;
    unsigned visited = 0;
    int64_t started = g_get_monotonic_time();
    while (!result) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (++visited > 128 || g_get_monotonic_time() - started >= 10000 ||
            !name_valid(entry->d_name)) { result = -1; break; }
        int task = openat(tasks, entry->d_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        struct stat before, after, path;
        char *raw = NULL;
        size_t size;
        GKeyFile *record = g_key_file_new();
        bool valid = task >= 0 && !fstat(task, &before) &&
            !read_file(tasks, entry->d_name, RECORD_LIMIT, &raw, &size) &&
            !fstat(task, &after) && object_stat_equal(&before, &after) &&
            !fstatat(tasks, entry->d_name, &path, AT_SYMLINK_NOFOLLOW) && object_stat_equal(&before, &path) &&
            !memchr(raw, 0, size) && g_key_file_load_from_data(record, raw, size, 0, NULL);
        char id[37];
        memcpy(id, entry->d_name, 36); id[36] = 0;
        bool copying = record_string_is(record, "task", "version", "2");
        const char *task_keys[] = {"version", "id", "state", "source", "build_id",
                                  copying ? "kind" : "environment_sha256"};
        valid = valid && (copying || record_string_is(record, "task", "version", "1")) &&
            exact_keys(record, "task", task_keys, G_N_ELEMENTS(task_keys)) &&
            record_string_is(record, "task", "id", id) && record_string_is(record, "task", "state", "BOUND");
        if (copying) valid &= record_string_is(record, "task", "kind", "COPY");
        const char *digests[] = {"source", "build_id", "environment_sha256"};
        for (unsigned i = 0; valid && i < (copying ? 2u : 3u); i++) {
            char *value = g_key_file_get_string(record, "task", digests[i], NULL);
            valid = digest_valid(value); g_free(value);
        }
        uint64_t device, inode;
        valid = valid && record_uint64(record, "cache", "device", &device) && device == (uint64_t)cache.st_dev &&
            record_uint64(record, "cache", "inode", &inode) && inode == (uint64_t)cache.st_ino;
        bool referenced = false;
        const char *roles[] = {"source", "tbset", "base_native", "base_module", "input"};
        gsize count;
        char **groups = g_key_file_get_groups(record, &count);
        for (gsize i = 0; valid && i < count; i++) {
            const char *group = groups[i];
            bool input = false;
            for (unsigned j = 0; j < G_N_ELEMENTS(roles); j++) input |= !strcmp(group, roles[j]);
            if (!input) {
                if (!strcmp(group, "task")) continue;
                bool location = !strcmp(group, "cache") || !strcmp(group, "temporary") || !strcmp(group, "collected");
                bool output = !strcmp(group, copying ? "output" : "output_native") ||
                    (!copying && !strcmp(group, "output_module"));
                const char *identity_fields[] = {"device", "inode", "size", "mode", "uid", "mtime_sec", "mtime_nsec"};
                const char *output_fields[] = {"name"};
                valid = location ? exact_keys(record, group, identity_fields, G_N_ELEMENTS(identity_fields)) &&
                    task_identity_valid(record, group) : output && exact_keys(record, group, output_fields, 1);
                if (valid && output) {
                    char *value = g_key_file_get_string(record, group, "name", NULL);
                    valid = value && *value && !strchr(value, '/') && strcmp(value, ".") && strcmp(value, "..");
                    g_free(value);
                }
                continue;
            }
            const char *fields[] = {"name", "directory", "device", "inode", "size", "mode", "uid", "mtime_sec", "mtime_nsec"};
            char *input_name = g_key_file_get_string(record, group, "name", NULL);
            char *location = g_key_file_get_string(record, group, "directory", NULL);
            valid = exact_keys(record, group, fields, G_N_ELEMENTS(fields)) && input_name && *input_name &&
                !strchr(input_name, '/') && strcmp(input_name, ".") && strcmp(input_name, "..") &&
                (!g_strcmp0(location, "cache") || !g_strcmp0(location, "temporary") || !g_strcmp0(location, "collected")) &&
                task_identity_valid(record, group) &&
                record_uint64(record, group, "device", &device) && record_uint64(record, group, "inode", &inode);
            valid &= copying ? !strcmp(group, "input") : strcmp(group, "input") != 0;
            if (valid) referenced |= (!strcmp(location, "cache") && !strcmp(input_name, name)) ||
                (device == (uint64_t)object->st_dev && inode == (uint64_t)object->st_ino);
            g_free(input_name); g_free(location);
        }
        valid = valid && g_key_file_has_group(record, copying ? "input" : "source") &&
            g_key_file_has_group(record, "temporary") &&
            g_key_file_has_group(record, copying ? "output" : "output_native") &&
            (copying || g_key_file_has_group(record, "output_module"));
        g_strfreev(groups);
        if (!valid) result = -1;
        else if (referenced) {
            int released = task_inputs_released(gc, entry->d_name, copying, task, &before);
            if (released > 0 && copying) {
                char *output = g_key_file_get_string(record, "output", "name", NULL);
                int temporary = open_directory(root, ".tmp", false);
                struct stat st;
                if (!output || !*output || strchr(output, '/') || !strcmp(output, ".") || !strcmp(output, "..") ||
                    temporary < 0 || !fstatat(temporary, output, &st, AT_SYMLINK_NOFOLLOW) || errno != ENOENT)
                    released = 0;
                if (temporary >= 0) close(temporary);
                g_free(output);
            }
            result = released < 0 ? -1 : released ? 0 : 1;
        }
        if (task >= 0) close(task);
        g_free(raw); g_key_file_unref(record);
    }
    closedir(directory); close(gc);
    return result;
}

static int object_transaction_status(int root, const char *name, const struct stat *object,
                                      const uint64_t *grace_us)
{
    int store = open_store(root, false);
    if (store < 0)
        return errno == ENOENT && (!grace_us || !*grace_us) ? 0 : -1;
    DIR *directory = fdopendir(store);
    if (!directory) { close(store); return -1; }
    int result = 0;
    unsigned visited = 0;
    int64_t started = g_get_monotonic_time();
    char *boot = NULL;
    uint64_t now_us = 0, latest_deadline = 0;
    bool retirement_observed = false;
    if (grace_us) {
        if (retirement_clock(&boot, &now_us)) result = -1;
    }
    while (!result) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char *raw = NULL;
        size_t size;
        if (++visited > 128 || g_get_monotonic_time() - started >= 10000 ||
            !name_valid(entry->d_name) || read_file(store, entry->d_name, RECORD_LIMIT, &raw, &size)) {
            result = -1; break;
        }
        GKeyFile *record = g_key_file_new();
        bool valid = !memchr(raw, 0, size) && g_key_file_load_from_data(record, raw, size, 0, NULL) &&
            record_shape_valid(record);
        char *source = g_key_file_get_string(record, "transaction", "source", NULL);
        char *previous64 = g_key_file_get_string(record, "transaction", "previous", NULL);
        char *next64 = g_key_file_get_string(record, "transaction", "next", NULL);
        char *objects64 = g_key_file_get_string(record, "transaction", "objects", NULL);
        char *state = g_key_file_get_string(record, "transaction", "state", NULL);
        gsize previous_size = 0, next_size = 0, object_size = 0;
        guchar *previous = previous64 ? decode_snapshot(previous64, &previous_size) : NULL;
        guchar *next = next64 ? decode_snapshot(next64, &next_size) : NULL;
        guchar *objects = objects64 ? g_base64_decode(objects64, &object_size) : NULL;
        char *canonical = objects ? g_base64_encode(objects, object_size) : NULL;
        valid = valid && source_valid(source) && previous && next && next_size &&
            (record_string_is(record, "transaction", "version", "1") ||
             record_string_is(record, "transaction", "version", "2")) && state &&
            (!strcmp(state, "PREPARED") || !strcmp(state, "RETIRED") ||
             !strcmp(state, "ABORTED") || !strcmp(state, "UNKNOWN"));
        GHashTable *refs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        valid = valid && (!previous_size || manifest_references(source, (char *)previous, previous_size, refs)) &&
            manifest_references(source, (char *)next, next_size, refs);
        bool referenced = valid && g_hash_table_contains(refs, name);
        bool retired = record_string_is(record, "transaction", "state", "RETIRED");
        bool bound = valid && objects && canonical && !strcmp(canonical, objects64) &&
            !latcd_retirement_validate_binding(source, (char *)previous, previous_size,
                (char *)next, next_size, (char *)objects, object_size);
        /* Legacy/unproven records cannot erase a root. A fully bound RETIRED
         * snapshot is history, not an indefinite hold on its former next set. */
        if (referenced && retired) {
            valid = bound && record_string_is(record, "transaction", "binding_status", "COMPLETE") &&
                record_string_is(record, "transaction", "objects_status", "RECORDED");
        }
        if (bound) {
            GKeyFile *evidence = g_key_file_new();
            valid &= g_key_file_load_from_data(evidence, (char *)objects, object_size, 0, NULL);
            int count = g_key_file_get_integer(evidence, "objects", "count", NULL);
            for (int i = 0; valid && i < count; i++) {
                char group[32];
                snprintf(group, sizeof(group), "object%d", i);
                char *candidate = g_key_file_get_string(evidence, group, "name", NULL);
                uint64_t device, inode, bytes, allocated;
                valid = record_uint64(evidence, group, "device", &device) &&
                    record_uint64(evidence, group, "inode", &inode) &&
                    record_uint64(evidence, group, "size", &bytes) &&
                    record_uint64(evidence, group, "allocated", &allocated);
                bool same_inode = valid && device == (uint64_t)object->st_dev && inode == (uint64_t)object->st_ino;
                if (!g_strcmp0(candidate, name) || same_inode) {
                    referenced = true;
                    valid = valid && same_inode && bytes == (uint64_t)object->st_size &&
                        allocated == (uint64_t)object->st_blocks * 512;
                }
                g_free(candidate);
            }
            g_key_file_unref(evidence);
        }
        if (valid && referenced && retired && grace_us) {
            GHashTable *old_refs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
            GHashTable *next_refs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
            valid = bound && record_string_is(record, "transaction", "binding_status", "COMPLETE") &&
                record_string_is(record, "transaction", "objects_status", "RECORDED") &&
                (!previous_size || manifest_references(source, (char *)previous, previous_size, old_refs)) &&
                manifest_references(source, (char *)next, next_size, next_refs);
            if (valid && g_hash_table_contains(old_refs, name) && !g_hash_table_contains(next_refs, name)) {
                uint64_t stamp;
                valid = record_string_is(record, "transaction", "retired_boot", boot) &&
                    record_uint64(record, "transaction", "retired_boottime_us", &stamp) &&
                    stamp <= now_us && *grace_us <= UINT64_MAX - stamp;
                if (valid) {
                    retirement_observed = true;
                    latest_deadline = MAX(latest_deadline, stamp + *grace_us);
                }
            }
            g_hash_table_unref(old_refs); g_hash_table_unref(next_refs);
        }
        result = !valid ? -1 : referenced && !retired ? 1 : 0;
        g_hash_table_unref(refs); g_free(canonical); g_free(objects); g_free(next); g_free(previous);
        g_free(state); g_free(objects64); g_free(next64); g_free(previous64); g_free(source);
        g_key_file_unref(record); g_free(raw);
    }
    if (!result && grace_us && (!retirement_observed || latest_deadline > now_us)) result = 1;
    g_free(boot);
    closedir(directory);
    return result;
}

int latcd_retirement_hold(const char *root, const char *source, const char *name,
                           const char *id, const char *reason, bool release,
                           char *error, size_t error_size)
{
    if (!source_valid(source) || !object_name_valid(source, name) || !hold_id_valid(id) ||
        (!reason || (strcmp(reason, "ROLLBACK") && strcmp(reason, "MIGRATION") && strcmp(reason, "EXTERNAL"))))
        return fail(error, error_size, "invalid explicit hold");
    int latch = lat_aot_v2_cache_source_lock(root, source, LOCK_EX | LOCK_NB, false, error, error_size);
    if (latch < 0) return -1;
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", true);
    int holds = gc < 0 ? -1 : open_directory(gc, "holds", true);
    int store = holds < 0 ? -1 : open_directory(holds, name, !release);
    struct stat cache, object;
    int fd = directory < 0 ? -1 : openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    int result = -1;
    char *filename = g_strdup_printf("%s.ini", id), *raw = NULL;
    size_t size;
    GKeyFile *record = g_key_file_new();
    if (store < 0 || fd < 0 || fstat(directory, &cache) || fstat(fd, &object) ||
        !S_ISREG(object.st_mode) || object.st_uid != geteuid() || object.st_nlink != 1 ||
        (object.st_mode & 0222) || object.st_size <= 0 || flock(fd, LOCK_SH | LOCK_NB)) goto out;
    if (!release) {
        int tombstones = open_directory(gc, "tombstones", false);
        struct stat marker;
        bool blocked = tombstones < 0 ? errno != ENOENT :
            !fstatat(tombstones, name, &marker, AT_SYMLINK_NOFOLLOW) || errno != ENOENT;
        if (tombstones >= 0) close(tombstones);
        if (blocked) goto out;
    }
    int status = read_file(store, filename, MANIFEST_LIMIT, &raw, &size);
    if (status < 0 || (release && status)) goto out;
    if (!status) {
        if (memchr(raw, 0, size) || !g_key_file_load_from_data(record, raw, size, 0, NULL) ||
            !hold_record_valid(record, id, name, &cache, &object)) goto out;
        char *existing_reason = g_key_file_get_string(record, "hold", "reason", NULL);
        char *state = g_key_file_get_string(record, "hold", "state", NULL);
        bool matched = !g_strcmp0(existing_reason, reason) && (release || !g_strcmp0(state, "ACTIVE"));
        g_free(existing_reason); g_free(state);
        if (!matched) goto out;
    } else {
        g_key_file_set_integer(record, "hold", "version", 1);
        g_key_file_set_string(record, "hold", "id", id);
        g_key_file_set_string(record, "hold", "name", name);
        g_key_file_set_string(record, "hold", "reason", reason);
        g_key_file_set_uint64(record, "hold", "cache_device", cache.st_dev);
        g_key_file_set_uint64(record, "hold", "cache_inode", cache.st_ino);
        g_key_file_set_uint64(record, "hold", "object_device", object.st_dev);
        g_key_file_set_uint64(record, "hold", "object_inode", object.st_ino);
    }
    struct stat after;
    if (fstatat(directory, name, &after, AT_SYMLINK_NOFOLLOW) ||
        !object_stat_equal(&object, &after)) goto out;
    g_key_file_set_string(record, "hold", "state", release ? "RELEASED" : "ACTIVE");
    result = write_record(store, filename, record);
out:
    g_free(raw); g_free(filename); g_key_file_unref(record);
    if (fd >= 0) close(fd);
    if (store >= 0) close(store);
    if (holds >= 0) close(holds);
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    close(latch);
    return result ? fail(error, error_size, "explicit object hold rejected or incomplete") : 0;
}

static bool mount_lease_fd_valid(const char *root, int gc, int lease_fd)
{
    int lock = openat(gc, "reference-roots.lock",
                      O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat held, path, cache;
    bool valid = lease_fd >= 0 && lock >= 0 && !fstat(lease_fd, &held) &&
        !fstat(lock, &path) && object_stat_equal(&held, &path) &&
        S_ISREG(held.st_mode) && held.st_uid == geteuid() && held.st_nlink == 1 &&
        !(held.st_mode & 0077) && !held.st_size && !fstatat(gc, "reference-roots.lock",
        &path, AT_SYMLINK_NOFOLLOW) && object_stat_equal(&held, &path) &&
        !flock(lease_fd, LOCK_SH | LOCK_NB);
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    valid = valid && directory >= 0 && !fstat(directory, &cache);
    if (directory >= 0) close(directory);
    if (lock >= 0) close(lock);
    return valid;
}

int latcd_retirement_mount_lease(const char *root, const char *id, const char *scope,
                                 const char *source, const char *name,
                                 char *error, size_t error_size)
{
    bool cache_scope = !g_strcmp0(scope, "CACHE");
    bool source_scope = !g_strcmp0(scope, "SOURCE");
    bool object_scope = !g_strcmp0(scope, "OBJECT");
    if (!root || !hold_id_valid(id) || (!cache_scope && !source_scope && !object_scope) ||
        ((source_scope || object_scope) && !source_valid(source)) ||
        (object_scope && !object_name_valid(source, name)) ||
        ((cache_scope || source_scope) && name && *name))
        return fail(error, error_size, "invalid mount lease");
    int roots = latcd_retirement_roots_lock(root, LOCK_SH | LOCK_NB, error, error_size);
    if (roots < 0) return -1;
    int directory = -1, gc = -1, store = -1, object_fd = -1, result = -1;
    struct stat cache, object = {0};
    GKeyFile *record = g_key_file_new();
    char *filename = g_strdup_printf("%s.ini", id);
    char *raw = NULL;
    size_t size = 0;
    directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    gc = directory < 0 ? -1 : open_directory(directory, ".gc", true);
    store = gc < 0 ? -1 : open_directory(gc, "mount-leases", true);
    if (store < 0 || fstat(directory, &cache)) goto out;
    const char *record_source = cache_scope ? "" : source;
    const char *record_name = object_scope ? name : "";
    if (object_scope) {
        object_fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (object_fd < 0 || fstat(object_fd, &object) || !S_ISREG(object.st_mode) ||
            object.st_uid != geteuid() || object.st_nlink != 1 ||
            (object.st_mode & 0222) || object.st_size <= 0 ||
            flock(object_fd, LOCK_SH | LOCK_NB)) goto out;
    }
    int status = read_file(store, filename, MANIFEST_LIMIT, &raw, &size);
    if (status < 0) goto out;
    if (!status) {
        MountLeaseRecord lease = {0};
        bool valid = !memchr(raw, 0, size) &&
            g_key_file_load_from_data(record, raw, size, 0, NULL) &&
            mount_lease_parse(record, id, &cache, &lease) &&
            !strcmp(lease.state, "ACTIVE") && !strcmp(lease.scope, scope) &&
            !strcmp(lease.source, record_source) && !strcmp(lease.name, record_name) &&
            (!object_scope || (lease.object_device == (uint64_t)object.st_dev &&
                               lease.object_inode == (uint64_t)object.st_ino));
        mount_lease_clear(&lease);
        if (!valid) goto out;
    } else {
        g_key_file_set_integer(record, "mount", "version", 1);
        g_key_file_set_string(record, "mount", "id", id);
        g_key_file_set_string(record, "mount", "scope", scope);
        g_key_file_set_string(record, "mount", "state", "ACTIVE");
        g_key_file_set_uint64(record, "mount", "cache_device", cache.st_dev);
        g_key_file_set_uint64(record, "mount", "cache_inode", cache.st_ino);
        g_key_file_set_string(record, "mount", "source", record_source);
        g_key_file_set_string(record, "mount", "name", record_name);
        g_key_file_set_uint64(record, "mount", "object_device", object.st_dev);
        g_key_file_set_uint64(record, "mount", "object_inode", object.st_ino);
        if (write_record(store, filename, record)) goto out;
    }
    result = roots;
    roots = -1;
out:
    if (roots >= 0) close(roots);
    if (object_fd >= 0) close(object_fd);
    if (store >= 0) close(store);
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    g_free(raw);
    g_free(filename);
    g_key_file_unref(record);
    return result >= 0 ? result : fail(error, error_size,
        "mount lease rejected or incomplete");
}

int latcd_retirement_mount_release(const char *root, const char *id, int lease_fd,
                                   char *error, size_t error_size)
{
    if (!root || !hold_id_valid(id) || lease_fd < 0)
        return fail(error, error_size, "invalid mount lease release");
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", false);
    int store = gc < 0 ? -1 : open_directory(gc, "mount-leases", false);
    struct stat cache, object = {0};
    int object_fd = -1, result = -1;
    char *filename = g_strdup_printf("%s.ini", id), *raw = NULL;
    size_t size = 0;
    GKeyFile *record = g_key_file_new();
    MountLeaseRecord lease = {0};
    if (store < 0 || fstat(directory, &cache) || !mount_lease_fd_valid(root, gc, lease_fd) ||
        read_file(store, filename, MANIFEST_LIMIT, &raw, &size) ||
        memchr(raw, 0, size) ||
        !g_key_file_load_from_data(record, raw, size, 0, NULL) ||
        !mount_lease_parse(record, id, &cache, &lease)) goto out;
    if (!strcmp(lease.scope, "OBJECT")) {
        object_fd = openat(directory, lease.name,
                           O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (object_fd < 0 || fstat(object_fd, &object) ||
            lease.object_device != (uint64_t)object.st_dev ||
            lease.object_inode != (uint64_t)object.st_ino) goto out;
    }
    if (!strcmp(lease.state, "ACTIVE")) {
        g_key_file_set_string(record, "mount", "state", "RELEASED");
        if (write_record(store, filename, record)) goto out;
    }
    result = 0;
out:
    mount_lease_clear(&lease);
    if (object_fd >= 0) close(object_fd);
    if (store >= 0) close(store);
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    g_free(raw);
    g_free(filename);
    g_key_file_unref(record);
    return result ? fail(error, error_size,
        "mount lease release rejected or incomplete") : 0;
}

static int retirement_tombstone(const char *root, const char *source,
                               const char *name, int object_fd, const char *evidence,
                               int source_latch,
                               char *error, size_t error_size)
{
    if (!source_valid(source) || !object_name_valid(source, name) || object_fd < 0 ||
        !evidence || strlen(evidence) >= 16384)
        return fail(error, error_size, "invalid tombstone object");
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", true);
    int store = gc < 0 ? -1 : open_directory(gc, "tombstones", true);
    int locks = source_latch < 0 || gc < 0 ? -1 : open_directory(gc, "source-locks", false);
    char *source_lock_name = g_strdup_printf("%s.lock", source);
    int roots = roots_lock_gc(gc, LOCK_EX | LOCK_NB, error, error_size);
    int result = -1;
    GKeyFile *record = g_key_file_new();
    GKeyFile *captured = g_key_file_new();
    char *captured_name = NULL, *hash = NULL;
    struct stat before, after, path;
    char *current = g_strdup_printf("%s.current", source), *manifest = NULL;
    size_t size = 0;
    if (store < 0 || roots < 0 || !directory_matches_at(directory, ".gc", gc) ||
        !directory_matches_at(gc, "tombstones", store) ||
        (source_latch >= 0 && (!directory_matches_at(gc, "source-locks", locks) ||
         !lock_matches_at(locks, source_lock_name, source_latch))) ||
        !lock_matches_at(gc, "reference-roots.lock", roots) ||
        flock(object_fd, LOCK_EX | LOCK_NB) ||
        fstat(object_fd, &before) || !S_ISREG(before.st_mode) ||
        before.st_uid != geteuid() || before.st_nlink != 1 ||
        (before.st_mode & 0222) || before.st_size <= 0 ||
        fstatat(directory, name, &path, AT_SYMLINK_NOFOLLOW) ||
        !object_stat_equal(&before, &path)) goto out;
    const char *header[] = {"count"};
    const char *fields[] = {"name", "device", "inode", "size", "allocated", "sha256"};
    gsize groups;
    char **group_names;
    if (!g_key_file_load_from_data(captured, evidence, -1, 0, NULL)) goto out;
    group_names = g_key_file_get_groups(captured, &groups);
    g_strfreev(group_names);
    if (groups != 2 || g_key_file_get_integer(captured, "objects", "count", NULL) != 1 ||
        !exact_keys(captured, "objects", header, G_N_ELEMENTS(header)) ||
        !exact_keys(captured, "object0", fields, G_N_ELEMENTS(fields))) goto out;
    captured_name = g_key_file_get_string(captured, "object0", "name", NULL);
    hash = g_key_file_get_string(captured, "object0", "sha256", NULL);
    if (g_strcmp0(captured_name, name) || !digest_valid(hash)) goto out;
    uint64_t expected[] = {before.st_dev, before.st_ino, before.st_size,
                          (uint64_t)before.st_blocks * 512};
    for (size_t i = 0; i < G_N_ELEMENTS(expected); i++) {
        char *value = g_key_file_get_string(captured, "object0", fields[i + 1], NULL);
        errno = 0;
        char *end = NULL;
        uint64_t number = value ? g_ascii_strtoull(value, &end, 10) : 0;
        bool valid = value && *value && strspn(value, "0123456789") == strlen(value) &&
            !errno && end && !*end && number == expected[i];
        g_free(value);
        if (!valid) goto out;
    }
    int status = read_file(directory, current, MANIFEST_LIMIT, &manifest, &size);
    if (status < 0) goto out;
    if (!status) {
        GHashTable *references = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        bool safe = manifest_references(source, manifest, size, references) &&
            !g_hash_table_contains(references, name);
        g_hash_table_unref(references);
        if (!safe) goto out;
    }
    if (object_current_status(directory, name) ||
        object_hold_status(directory, name, &before) || object_task_status(directory, name, &before) ||
        object_transaction_status(directory, name, &before, NULL) ||
        mount_lease_status(directory, gc, source, name, &before) ||
        fstat(object_fd, &after) || !object_stat_equal(&before, &after) ||
        fstatat(directory, name, &path, AT_SYMLINK_NOFOLLOW) ||
        !object_stat_equal(&before, &path)) goto out;
    /* Never replace earlier intent: its identity is crash-recovery evidence. */
    if (!fstatat(store, name, &path, AT_SYMLINK_NOFOLLOW) || errno != ENOENT) goto out;
    g_key_file_set_integer(record, "tombstone", "version", 1);
    g_key_file_set_string(record, "tombstone", "source", source);
    g_key_file_set_string(record, "tombstone", "name", name);
    g_key_file_set_string(record, "tombstone", "state", "DELETING");
    g_key_file_set_uint64(record, "tombstone", "device", before.st_dev);
    g_key_file_set_uint64(record, "tombstone", "inode", before.st_ino);
    g_key_file_set_uint64(record, "tombstone", "size", before.st_size);
    g_key_file_set_uint64(record, "tombstone", "allocated", (uint64_t)before.st_blocks * 512);
    g_key_file_set_string(record, "tombstone", "sha256", hash);
    if (!directory_matches_at(directory, ".gc", gc) ||
        !directory_matches_at(gc, "tombstones", store) ||
        (source_latch >= 0 && (!directory_matches_at(gc, "source-locks", locks) ||
         !lock_matches_at(locks, source_lock_name, source_latch))) ||
        !lock_matches_at(gc, "reference-roots.lock", roots)) goto out;
    result = write_record(store, name, record);
out:
    g_free(manifest);
    g_free(source_lock_name);
    g_free(current);
    g_key_file_unref(record);
    g_key_file_unref(captured);
    g_free(captured_name);
    g_free(hash);
    if (store >= 0) close(store);
    if (locks >= 0) close(locks);
    if (gc >= 0) close(gc);
    if (directory >= 0) close(directory);
    if (roots >= 0) close(roots);
    return result ? fail(error, error_size, "cannot persist object deletion intent") : 0;
}

int latcd_retirement_tombstone(const char *root, const char *source,
                               const char *name, int object_fd, const char *evidence,
                               char *error, size_t error_size)
{
    return retirement_tombstone(root, source, name, object_fd, evidence, -1,
                                error, error_size);
}

/* No pathname here is trusted until its source-bound basename is checked.
 * Content hashing is reserved for startup, outside daemon metadata locks. */
static bool tombstone_shape(GKeyFile *record, const char *name,
                             char **source, uint64_t values[4], char **hash);

static int completed_removal(int root, const char *root_path, const char *source,
                             const char *name, const uint64_t expected[4],
                             const char *digest)
{
    int gc = open_directory(root, ".gc", false);
    int store = gc < 0 ? -1 : open_directory(gc, "tombstones", false);
    char *raw = NULL, *stored_source = NULL, *hash = NULL;
    size_t size = 0;
    uint64_t values[4] = {0};
    GKeyFile *record = g_key_file_new();
    bool valid = store >= 0 && !read_file(store, name, RECORD_LIMIT, &raw, &size) &&
        !memchr(raw, 0, size) && g_key_file_load_from_data(record, raw, size, 0, NULL) &&
        tombstone_shape(record, name, &stored_source, values, &hash) &&
        !g_strcmp0(source, stored_source) && !g_strcmp0(digest, hash) &&
        !memcmp(values, expected, sizeof(values));
    char *deletion = g_key_file_get_string(record, "tombstone", "deletion_status", NULL);
    char *observation = g_key_file_get_string(record, "tombstone", "recovery_status", NULL);
    bool complete = !g_strcmp0(deletion, "UNLINKED") && !g_strcmp0(observation, "MISSING");
    bool pending = !deletion && (!observation || !strcmp(observation, "MATCHED") ||
                                !strcmp(observation, "MISSING"));
    valid = valid && (complete || (root_path && pending));
    int latch = -1, result = 0;
    if (valid && !complete) {
        latch = lat_aot_v2_cache_source_lock(root_path, source, LOCK_EX | LOCK_NB,
                                             false, NULL, 0);
        if (latch < 0) { result = -1; valid = false; }
    }
    /* A receipt cannot erase a current reference, even if the file is absent. */
    char *current = g_strdup_printf("%s.current", source), *manifest = NULL;
    size_t manifest_size = 0;
    GHashTable *references = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    if (valid) valid = !read_file(root, current, MANIFEST_LIMIT, &manifest, &manifest_size) &&
        manifest_references(source, manifest, manifest_size, references) &&
        !g_hash_table_contains(references, name);
    struct stat st;
    if (valid) valid = fstatat(root, name, &st, AT_SYMLINK_NOFOLLOW) && errno == ENOENT;
    if (valid && !complete) {
        /* Observation only: make the already-absent name durable. Never unlink
         * here, and never infer physical block release from this receipt. */
        if (fsync(root) || record_write_fault("missing-synced")) result = -1;
        else {
            g_key_file_set_string(record, "tombstone", "deletion_status", "UNLINKED");
            g_key_file_set_string(record, "tombstone", "recovery_status", "MISSING");
            result = write_recovery_record(store, name, record) ? -1 : 1;
        }
    } else if (valid) result = 1;
    if (latch >= 0) close(latch);
    g_hash_table_unref(references);
    g_free(manifest); g_free(current); g_free(deletion); g_free(observation);
    g_free(raw); g_free(stored_source); g_free(hash); g_key_file_unref(record);
    if (store >= 0) close(store);
    if (gc >= 0) close(gc);
    return result;
}

static int verify_objects(int root, const char *root_path, const char *source, const char *encoded,
                           bool content, bool allow_removed, LatcdRecoveryCursor *cursor)
{
    if (!encoded) return -1;
    if (!*encoded) return 2;
    gsize size;
    guchar *raw = g_base64_decode(encoded, &size);
    char *canonical = g_base64_encode(raw, size);
    bool valid = size && size < 16384 && !strcmp(canonical, encoded) && !memchr(raw, 0, size);
    GKeyFile *objects = g_key_file_new();
    valid = valid && g_key_file_load_from_data(objects, (char *)raw, size, 0, NULL);
    g_free(canonical);
    g_free(raw);
    int result = -1;
    if (!valid) goto out;
    const char *header[] = {"count"};
    const char *fields[] = {"name", "device", "inode", "size", "allocated", "sha256"};
    int count = g_key_file_get_integer(objects, "objects", "count", NULL);
    gsize group_count;
    char **groups = g_key_file_get_groups(objects, &group_count);
    valid = count > 0 && count <= 6 && group_count == (gsize)count + 1 &&
        exact_keys(objects, "objects", header, G_N_ELEMENTS(header));
    g_strfreev(groups);
    if (!valid) goto out;
    result = 0;
    for (int i = 0; i < count; i++) {
        char group[32];
        snprintf(group, sizeof(group), "object%d", i);
        if (!exact_keys(objects, group, fields, G_N_ELEMENTS(fields))) { result = -1; break; }
        char *name = g_key_file_get_string(objects, group, "name", NULL);
        char *hash = g_key_file_get_string(objects, group, "sha256", NULL);
        valid = object_name_valid(source, name) && hash && strlen(hash) == 64 &&
            strspn(hash, "0123456789abcdef") == 64;
        uint64_t values[4] = {0};
        for (size_t j = 0; valid && j < G_N_ELEMENTS(values); j++) {
            char *value = g_key_file_get_string(objects, group, fields[j + 1], NULL);
            char *end = NULL;
            errno = 0;
            values[j] = value ? g_ascii_strtoull(value, &end, 10) : 0;
            valid = value && *value && strspn(value, "0123456789") == strlen(value) &&
                end && !*end && !errno;
            g_free(value);
        }
        if (!valid) result = -1;
        else {
            struct stat st;
            int status = fstatat(root, name, &st, AT_SYMLINK_NOFOLLOW);
            int removed = status && errno == ENOENT && allow_removed ?
                completed_removal(root, root_path, source, name, values, hash) : 0;
            if (removed < 0) result = -1;
            else if (removed) {
                /* Durable exact-object receipt replaces only missing content. */
            } else if (status || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
                st.st_nlink != 1 || (st.st_mode & 0222) ||
                (uint64_t)st.st_dev != values[0] || (uint64_t)st.st_ino != values[1] ||
                (uint64_t)st.st_size != values[2] || (uint64_t)st.st_blocks * 512 != values[3]) {
                result = 1;
            } else if (content) {
                /* Reuse the same fd/lease/hash checks as publication capture. */
                const char *names[] = {name};
                char *actual = cursor ? recovery_capture(root, source, name, cursor) :
                    capture_objects(root, source, names, 1);
                if (cursor && cursor->yielded) {
                    g_free(hash); g_free(name);
                    result = 3;
                    break;
                }
                GKeyFile *observed = g_key_file_new();
                char *actual_hash = NULL;
                if (actual && g_key_file_load_from_data(observed, actual, -1, 0, NULL))
                    actual_hash = g_key_file_get_string(observed, "object0", "sha256", NULL);
                if (g_strcmp0(hash, actual_hash)) result = 1;
                for (size_t j = 0; actual_hash && j < G_N_ELEMENTS(values); j++) {
                    if (g_key_file_get_uint64(observed, "object0", fields[j + 1], NULL) != values[j])
                        result = 1;
                }
                g_free(actual_hash);
                g_free(actual);
                g_key_file_unref(observed);
            }
        }
        g_free(hash);
        g_free(name);
        if (result) break;
    }
out:
    g_key_file_unref(objects);
    return result;
}

static int recover_record(int root, int store, const char *name, bool content,
                           LatcdRecoveryCursor *cursor)
{
    char *raw = NULL;
    size_t size;
    if (!name_valid(name) || read_file(store, name, RECORD_LIMIT, &raw, &size)) return -1;
    GKeyFile *record = g_key_file_new();
    int result = -1;
    if (memchr(raw, 0, size) ||
        !g_key_file_load_from_data(record, raw, size, G_KEY_FILE_NONE, NULL) ||
        !record_shape_valid(record)) goto out;
    char *source = g_key_file_get_string(record, "transaction", "source", NULL);
    char *state = g_key_file_get_string(record, "transaction", "state", NULL);
    char *old64 = g_key_file_get_string(record, "transaction", "previous", NULL);
    char *new64 = g_key_file_get_string(record, "transaction", "next", NULL);
    int version = g_key_file_get_integer(record, "transaction", "version", NULL);
    if ((version != 1 && version != 2) ||
        !source_valid(source) || !state || !old64 || !new64) goto fields_out;
    gsize old_size, new_size;
    guchar *old = decode_snapshot(old64, &old_size);
    guchar *next = decode_snapshot(new64, &new_size);
    if (!old || !next || !new_size) {
        g_free(old);
        g_free(next);
        goto fields_out;
    }
    if (version == 2) {
        char *encoded = g_key_file_get_string(record, "transaction", "objects", NULL);
        gsize object_size = 0;
        guchar *object_data = encoded ? g_base64_decode(encoded, &object_size) : NULL;
        bool bound = object_size && !latcd_retirement_validate_binding(source,
            (char *)old, old_size, (char *)next, new_size, (char *)object_data, object_size);
        int object_result = verify_objects(root, cursor ? cursor->root_path : NULL,
            source, encoded, content, bound && !strcmp(state, "RETIRED"), cursor);
        g_free(object_data);
        g_free(encoded);
        if (object_result == 3) { result = 1; goto snapshots_out; }
        if (object_result < 0) goto snapshots_out;
        g_key_file_set_string(record, "transaction", "binding_status",
                              bound ? "COMPLETE" : "UNPROVEN");
        g_key_file_set_string(record, "transaction", "objects_status",
            object_result == 2 ? "UNPROVEN" : object_result ? "MISMATCH" : "RECORDED");
        if (object_result == 1 || (object_size && !bound)) {
            g_key_file_set_string(record, "transaction", "state", "UNKNOWN");
            result = write_record(store, name, record);
            goto snapshots_out;
        }
    }
    if (strcmp(state, "PREPARED")) {
        result = (!strcmp(state, "RETIRED") || !strcmp(state, "ABORTED") ||
                  !strcmp(state, "UNKNOWN")) ? 0 : -1;
        if (!strcmp(state, "RETIRED")) {
            char *old_boot = g_key_file_get_string(record, "transaction", "retired_boot", NULL);
            char *boot = NULL;
            uint64_t stamp;
            if (!retirement_clock(&boot, &stamp)) {
                if (g_strcmp0(boot, old_boot)) {
                    g_key_file_set_string(record, "transaction", "retired_boot", boot);
                    g_key_file_set_uint64(record, "transaction", "retired_boottime_us", stamp);
                    g_key_file_set_string(record, "transaction", "retirement_clock_reason",
                                           old_boot ? "BOOT_CHANGED" : "CLOCK_MISSING");
                    result = write_record(store, name, record);
                }
            } else result = -1;
            g_free(boot);
            g_free(old_boot);
        }
        goto snapshots_out;
    }
    char *current = g_strdup_printf("%s.current", source);
    char *contents = NULL;
    size_t current_size;
    int status = read_file(root, current, MANIFEST_LIMIT, &contents, &current_size);
    const char *outcome = "UNKNOWN";
    if (!status && new_size && new_size <= MANIFEST_LIMIT &&
        current_size == new_size && !memcmp(contents, next, new_size)) {
        /* Restamp on recovery: never infer elapsed grace from wall time. */
        outcome = "RETIRED";
        if (set_clock(record, "retired")) {
            g_free(contents); g_free(current);
            goto snapshots_out;
        }
    } else if ((status == 1 && !old_size) ||
               (!status && old_size && old_size <= MANIFEST_LIMIT &&
                current_size == old_size && !memcmp(contents, old, old_size))) {
        outcome = "ABORTED";
    }
    g_key_file_set_string(record, "transaction", "state", outcome);
    result = !strcmp(outcome, "RETIRED") ? write_recovery_record(store, name, record) :
        write_record(store, name, record);
    g_free(contents);
    g_free(current);
snapshots_out:
    g_free(old);
    g_free(next);
fields_out:
    g_free(source);
    g_free(state);
    g_free(old64);
    g_free(new64);
out:
    g_key_file_unref(record);
    g_free(raw);
    return result;
}

static int retirement_finish(int root_fd, const char *transaction,
                           char *error, size_t error_size)
{
    int store = open_store(root_fd, false);
    int result = store < 0 || fsync(root_fd) ? -1 :
                 recover_record(root_fd, store, transaction, false, NULL);
    if (store >= 0) close(store);
    return result ? fail(error, error_size, "cannot complete retirement transaction") : 0;
}

struct LatcdRetirementPublication {
    char *root;
    char *transaction;
    int root_fd, gc_fd, roots_fd;
};

static bool publication_bound(LatcdRetirementPublication *publication)
{
    struct stat held, path;
    return !fstat(publication->root_fd, &held) && !lstat(publication->root, &path) &&
        held.st_dev == path.st_dev && held.st_ino == path.st_ino &&
        !fstat(publication->gc_fd, &held) &&
        !fstatat(publication->root_fd, ".gc", &path, AT_SYMLINK_NOFOLLOW) &&
        held.st_dev == path.st_dev && held.st_ino == path.st_ino &&
        !fstat(publication->roots_fd, &held) &&
        !fstatat(publication->gc_fd, "reference-roots.lock", &path, AT_SYMLINK_NOFOLLOW) &&
        object_stat_equal(&held, &path);
}

LatcdRetirementPublication *latcd_retirement_publication_open(
    const char *root, char *error, size_t error_size)
{
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", true);
    int fd = roots_lock_gc(gc, LOCK_SH, error, error_size);
    if (fd < 0) {
        if (gc >= 0) close(gc);
        if (directory >= 0) close(directory);
        return NULL;
    }
    LatcdRetirementPublication *publication = g_new0(LatcdRetirementPublication, 1);
    publication->root = g_strdup(root);
    publication->root_fd = directory;
    publication->gc_fd = gc;
    publication->roots_fd = fd;
    if (!publication_bound(publication)) {
        latcd_retirement_publication_close(publication);
        fail(error, error_size, "retirement publication directory binding changed");
        return NULL;
    }
    return publication;
}

int latcd_retirement_publication_prepare(LatcdRetirementPublication *publication,
    const char *source, const char *next, size_t next_size, const char *objects,
    char *error, size_t error_size)
{
    if (!publication || publication->transaction || !publication_bound(publication))
        return fail(error, error_size, "invalid retirement publication state");
    return retirement_prepare(publication->root_fd, source, next, next_size,
                                    objects, &publication->transaction, error, error_size);
}

int latcd_retirement_publication_finish(LatcdRetirementPublication *publication,
    char *error, size_t error_size)
{
    if (!publication || !publication->transaction || !publication_bound(publication))
        return fail(error, error_size, "retirement publication not prepared");
    int result = retirement_finish(publication->root_fd, publication->transaction,
                                         error, error_size);
    if (!result) g_clear_pointer(&publication->transaction, g_free);
    return result;
}

void latcd_retirement_publication_close(LatcdRetirementPublication *publication)
{
    if (!publication) return;
    close(publication->roots_fd);
    close(publication->gc_fd);
    close(publication->root_fd);
    g_free(publication->transaction);
    g_free(publication->root);
    g_free(publication);
}

int latcd_retirement_recover(const char *root, unsigned *recovered,
                            char *error, size_t error_size)
{
    *recovered = 0;
    LatcdRecoveryCursor *cursor = latcd_recovery_open(root, false, error, error_size);
    if (!cursor) return -1;
    LatcdRecoveryProgress progress;
    int result;
    do { result = latcd_recovery_step(cursor, 32, 4 * 1024 * 1024, 10000,
                                      &progress, error, error_size); } while (result > 0);
    *recovered = progress.recovered;
    latcd_recovery_close(cursor);
    return result;
}

static bool tombstone_shape(GKeyFile *record, const char *name,
                             char **source, uint64_t values[4], char **hash)
{
    const char *required[] = {"version", "source", "name", "state", "device",
        "inode", "size", "allocated", "sha256"};
    const char *optional[] = {"recovery_status", "deletion_status"};
    gsize count;
    char **groups = g_key_file_get_groups(record, &count);
    bool valid = count == 1 && !strcmp(groups[0], "tombstone");
    g_strfreev(groups);
    char **keys = g_key_file_get_keys(record, "tombstone", &count, NULL);
    GHashTable *seen = g_hash_table_new(g_str_hash, g_str_equal);
    for (gsize i = 0; valid && i < count; i++) {
        bool known = false;
        for (size_t j = 0; j < G_N_ELEMENTS(required); j++) known |= !strcmp(keys[i], required[j]);
        for (size_t j = 0; j < G_N_ELEMENTS(optional); j++) known |= !strcmp(keys[i], optional[j]);
        valid = known && g_hash_table_add(seen, keys[i]);
    }
    for (size_t i = 0; valid && i < G_N_ELEMENTS(required); i++)
        valid = g_hash_table_contains(seen, required[i]);
    g_hash_table_unref(seen);
    g_strfreev(keys);
    char *version = g_key_file_get_string(record, "tombstone", "version", NULL);
    char *stored_name = g_key_file_get_string(record, "tombstone", "name", NULL);
    char *state = g_key_file_get_string(record, "tombstone", "state", NULL);
    char *observation = g_key_file_get_string(record, "tombstone", "recovery_status", NULL);
    char *deletion = g_key_file_get_string(record, "tombstone", "deletion_status", NULL);
    *source = g_key_file_get_string(record, "tombstone", "source", NULL);
    *hash = g_key_file_get_string(record, "tombstone", "sha256", NULL);
    valid = valid && !g_strcmp0(version, "1") && source_valid(*source) &&
        object_name_valid(*source, name) && !g_strcmp0(name, stored_name) &&
        !g_strcmp0(state, "DELETING") && digest_valid(*hash) &&
        (!observation || !strcmp(observation, "MATCHED") || !strcmp(observation, "MISSING") ||
         !strcmp(observation, "UNKNOWN") || !strcmp(observation, "BUSY")) &&
        (!deletion || !strcmp(deletion, "UNLINKED"));
    const char *fields[] = {"device", "inode", "size", "allocated"};
    for (size_t i = 0; valid && i < G_N_ELEMENTS(fields); i++) {
        char *text = g_key_file_get_string(record, "tombstone", fields[i], NULL);
        char *end = NULL;
        errno = 0;
        values[i] = text ? g_ascii_strtoull(text, &end, 10) : 0;
        valid = text && *text && strspn(text, "0123456789") == strlen(text) &&
            end && !*end && !errno && (i != 2 || values[i]);
        g_free(text);
    }
    g_free(version); g_free(stored_name); g_free(state); g_free(observation); g_free(deletion);
    return valid;
}

static int recover_tombstone(const char *root_path, int root, int store,
                              const char *name, bool remove_object, LatcdRecoveryCursor *cursor,
                              const uint64_t *grace_us, LatcdRetirementDeletionReport *report)
{
    char *raw = NULL, *source = NULL, *hash = NULL;
    size_t size;
    uint64_t values[4] = {0};
    GKeyFile *record = g_key_file_new();
    int result = -1, object = -1, latch = -1, roots = -1, gc = -1;
    if (read_file(store, name, RECORD_LIMIT, &raw, &size) || memchr(raw, 0, size) ||
        !g_key_file_load_from_data(record, raw, size, 0, NULL) ||
        !tombstone_shape(record, name, &source, values, &hash)) goto out;
    char *prior = g_key_file_get_string(record, "tombstone", "recovery_status", NULL);
    bool unknown = !g_strcmp0(prior, "UNKNOWN");
    bool was_missing = !g_strcmp0(prior, "MISSING");
    bool was_unlinked = g_key_file_has_key(record, "tombstone", "deletion_status", NULL);
    const char *observation = unknown ? "UNKNOWN" : "MATCHED";
    bool missing = false;
    struct stat before = {0}, after, path;
    /* Hash outside S. Release this pin before S acquisition; final metadata
     * equality under S+G detects replacement/mutation during the handoff. */
    if (!unknown) {
        object = openat(root, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (object < 0) {
            missing = errno == ENOENT;
            observation = missing ? "MISSING" : "UNKNOWN";
        } else if (was_missing || was_unlinked) {
            observation = "UNKNOWN";
        } else if (flock(object, LOCK_SH | LOCK_NB)) {
            observation = errno == EWOULDBLOCK ? "BUSY" : "UNKNOWN";
        } else {
            const char *names[] = {name};
            char *actual = !fstat(object, &before) ?
                (cursor ? recovery_capture(root, source, name, cursor) :
                 capture_objects(root, source, names, 1)) : NULL;
            if (cursor && cursor->yielded) {
                g_free(prior); result = 1; goto out;
            }
            GKeyFile *captured = g_key_file_new();
            char *actual_hash = NULL;
            if (actual && g_key_file_load_from_data(captured, actual, -1, 0, NULL))
                actual_hash = g_key_file_get_string(captured, "object0", "sha256", NULL);
            if (g_strcmp0(actual_hash, hash) ||
                (uint64_t)before.st_dev != values[0] || (uint64_t)before.st_ino != values[1] ||
                (uint64_t)before.st_size != values[2] || (uint64_t)before.st_blocks * 512 != values[3] ||
                fstat(object, &after) || !object_stat_equal(&before, &after) ||
                fstatat(root, name, &path, AT_SYMLINK_NOFOLLOW) || !object_stat_equal(&before, &path))
                observation = "UNKNOWN";
            g_free(actual_hash); g_free(actual); g_key_file_unref(captured);
        }
        if (object >= 0) { close(object); object = -1; }
    }
    latch = lat_aot_v2_cache_source_lock(root_path, source, LOCK_EX | LOCK_NB,
                                         false, NULL, 0);
    if (latch < 0 || (remove_object && (roots = latcd_retirement_roots_lock(
            root_path, LOCK_EX | LOCK_NB, NULL, 0)) < 0)) {
        observation = !strcmp(observation, "UNKNOWN") || errno != EWOULDBLOCK ? "UNKNOWN" : "BUSY";
    } else {
        gc = open_directory(root, ".gc", false);
        int locks = gc < 0 ? -1 : open_directory(gc, "source-locks", false);
        char *lock_name = g_strdup_printf("%s.lock", source);
        bool bound = lock_matches_at(locks, lock_name, latch) &&
            (!remove_object || lock_matches_at(gc, "reference-roots.lock", roots));
        g_free(lock_name);
        if (locks >= 0) close(locks);
        if (!bound) { g_free(prior); goto out; }
        int mounted = gc < 0 ? -1 : mount_lease_status(
            root, gc, source, name, &before);
        if (mounted > 0) observation = "BUSY";
        else if (mounted < 0) observation = "UNKNOWN";
        char *current = g_strdup_printf("%s.current", source), *manifest = NULL;
        size_t manifest_size = 0;
        int status = read_file(root, current, MANIFEST_LIMIT, &manifest, &manifest_size);
        if (status < 0) observation = "UNKNOWN";
        if (!status) {
            GHashTable *references = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
            if (!manifest_references(source, manifest, manifest_size, references) ||
                g_hash_table_contains(references, name)) observation = "UNKNOWN";
            g_hash_table_unref(references);
        }
        g_free(current); g_free(manifest);
        if (!strcmp(observation, "MATCHED")) {
            object = openat(root, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            if (object < 0) observation = "UNKNOWN";
            else if (flock(object, LOCK_EX | LOCK_NB))
                observation = errno == EWOULDBLOCK ? "BUSY" : "UNKNOWN";
            else if (fstat(object, &after) || !object_stat_equal(&before, &after) ||
                fstatat(root, name, &path, AT_SYMLINK_NOFOLLOW) || !object_stat_equal(&before, &path))
                observation = "UNKNOWN";
        } else if (!strcmp(observation, "MISSING")) {
            if (!fstatat(root, name, &path, AT_SYMLINK_NOFOLLOW) || errno != ENOENT || fsync(root))
                observation = "UNKNOWN";
        }
    }
    if (remove_object && !strcmp(observation, "MATCHED")) {
        int held = object_current_status(root, name);
        if (!held) held = object_hold_status(root, name, &after);
        if (!held) held = object_task_status(root, name, &after);
        if (!held) held = object_transaction_status(root, name, &after, grace_us);
        if (held) observation = held < 0 ? "UNKNOWN" : "BUSY";
    }
    if (remove_object && (!strcmp(observation, "MATCHED") || !strcmp(observation, "MISSING"))) {
        /* Persist/confirm intent before dropping S. Readers refuse this name;
         * G remains exclusive through unlink, fsync and progress publication. */
        if (fsync(store)) { g_free(prior); goto out; }
        close(latch);
        latch = -1;
        if (!strcmp(observation, "MATCHED")) {
            if (report) {
                report->logical_bytes = before.st_size;
                report->allocated_bytes_before = (uint64_t)before.st_blocks * 512;
            }
            if (record_write_fault("before-unlink") ||
                unlinkat(root, name, 0)) {
                g_free(prior); goto out;
            }
            if (report) {
                report->object_unlinked = true;
                report->unlinked_allocated_bytes = report->allocated_bytes_before;
            }
            if (record_write_fault("unlinked")) { g_free(prior); goto out; }
        }
        if (fsync(root)) {
            g_free(prior); goto out;
        }
        if (report) report->namespace_durable = true;
        if (record_write_fault("unlink-synced")) { g_free(prior); goto out; }
        g_key_file_set_string(record, "tombstone", "deletion_status", "UNLINKED");
        observation = "MISSING";
    }
    g_key_file_set_string(record, "tombstone", "recovery_status", observation);
    if (!remove_object && !g_strcmp0(prior, observation)) result = 0;
    else if (!strcmp(observation, "MISSING"))
        result = write_recovery_record(store, name, record);
    else result = write_record(store, name, record);
    if (remove_object && strcmp(observation, "MISSING")) result = -1;
    if (report && !result && remove_object) report->receipt_durable = true;
    g_free(prior);
out:
    if (gc >= 0) close(gc);
    if (object >= 0) close(object);
    if (latch >= 0) close(latch);
    if (roots >= 0) close(roots);
    g_free(raw); g_free(source); g_free(hash);
    g_key_file_unref(record);
    return result;
}

int latcd_tombstone_recover(const char *root, unsigned *recovered,
                            char *error, size_t error_size)
{
    *recovered = 0;
    LatcdRecoveryCursor *cursor = latcd_recovery_open(root, true, error, error_size);
    if (!cursor) return -1;
    LatcdRecoveryProgress progress;
    int result;
    do { result = latcd_recovery_step(cursor, 32, 4 * 1024 * 1024, 10000,
                                      &progress, error, error_size); } while (result > 0);
    *recovered = progress.recovered;
    latcd_recovery_close(cursor);
    return result;
}

static bool filesystem_available(int fd, uint64_t *bytes)
{
    struct statvfs status;
    if (fstatvfs(fd, &status) || !status.f_frsize ||
        status.f_bavail > UINT64_MAX / status.f_frsize) return false;
    *bytes = (uint64_t)status.f_bavail * status.f_frsize;
    return true;
}

static int tombstone_delete_cursor(const char *root, const char *name, const uint64_t *grace_us,
                             LatcdRecoveryCursor *cursor,
                             LatcdRetirementDeletionReport *report,
                             char *error, size_t error_size)
{
    if (report) memset(report, 0, sizeof(*report));
    if (!name || strlen(name) < 64 || strchr(name, '/'))
        return fail(error, error_size, "invalid deletion object name");
    char source[65];
    memcpy(source, name, 64); source[64] = 0;
    if (!source_valid(source) || !object_name_valid(source, name))
        return fail(error, error_size, "invalid deletion object name");
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int gc = directory < 0 ? -1 : open_directory(directory, ".gc", false);
    int store = gc < 0 ? -1 : open_directory(gc, "tombstones", false);
    if (report && directory >= 0)
        report->filesystem_before_valid = filesystem_available(directory, &report->filesystem_available_before);
    int result = store < 0 ? -1 : recover_tombstone(root, directory, store, name, true, cursor, grace_us, report);
    if (store >= 0) close(store);
    if (gc >= 0) close(gc);
    if (report && directory >= 0)
        report->filesystem_after_valid = filesystem_available(directory, &report->filesystem_available_after);
    if (directory >= 0) close(directory);
    if (result > 0 && cursor && cursor->yielded) return 1;
    return result ? fail(error, error_size, "object deletion deferred or rejected") : 0;
}

static int tombstone_delete(const char *root, const char *name, const uint64_t *grace_us,
                             LatcdRetirementDeletionReport *report,
                             char *error, size_t error_size)
{
    return tombstone_delete_cursor(root, name, grace_us, NULL, report, error, error_size);
}

int latcd_tombstone_delete(const char *root, const char *name, char *error, size_t error_size)
{
    return tombstone_delete(root, name, NULL, NULL, error, error_size);
}

int latcd_tombstone_delete_due(const char *root, const char *name, uint64_t grace_us,
                               char *error, size_t error_size)
{
    return tombstone_delete(root, name, &grace_us, NULL, error, error_size);
}

int latcd_tombstone_delete_report(const char *root, const char *name,
    LatcdRetirementDeletionReport *report, char *error, size_t error_size)
{
    return tombstone_delete(root, name, NULL, report, error, error_size);
}

int latcd_tombstone_delete_due_report(const char *root, const char *name, uint64_t grace_us,
    LatcdRetirementDeletionReport *report, char *error, size_t error_size)
{
    return tombstone_delete(root, name, &grace_us, report, error, error_size);
}

typedef struct RetirementCandidate {
    uint64_t deadline, enqueued, epoch;
    uint64_t last_attempt, retry_at;
    unsigned busy_count;
} RetirementCandidate;

struct LatcdRetirementQueue {
    char *root;
    dev_t root_device;
    ino_t root_inode;
    bool root_bound;
    uint64_t grace, epoch;
    uint64_t diagnostic_cutoff, diagnostic_last_time;
    char diagnostic_boot[37], diagnostic_after[138];
    unsigned visited;
    bool aggregating, aggregation_verified, discovery_overflow;
    DIR *cursor;
    int discovery_watch;
    int discovery_tombstones;
    struct stat discovery_store;
    struct stat discovery_tombstone_store;
    GHashTable *candidates;
    GHashTable *discovered;
    GHashTable *discovered_keys;
    GHashTable *confirmed_keys;
    bool complete, persistence_uncertain;
    char last_source[65];
    LatcdRetirementAttempt active;
    uint64_t sequence;
    LatcdRecoveryCursor *execution;
    uint64_t execution_started;
};

static bool queue_bind_root(LatcdRetirementQueue *queue, int fd)
{
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || !S_ISDIR(st.st_mode)) {
        if (queue->root_bound) {
            queue->complete = false;
            queue->persistence_uncertain = true;
        }
        return false;
    }
    if (queue->root_bound) {
        bool matches = queue->root_device == st.st_dev && queue->root_inode == st.st_ino;
        if (!matches) {
            queue->complete = false;
            queue->persistence_uncertain = true;
        }
        return matches;
    }
    queue->root_device = st.st_dev;
    queue->root_inode = st.st_ino;
    queue->root_bound = true;
    return true;
}

LatcdRetirementQueue *latcd_retirement_queue_new(const char *root, uint64_t grace_us)
{
    LatcdRetirementQueue *queue = g_new0(LatcdRetirementQueue, 1);
    queue->discovery_watch = -1;
    queue->discovery_tombstones = -1;
    queue->root = g_strdup(root);
    queue->grace = grace_us;
    queue->candidates = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    queue->discovered = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    queue->discovered_keys = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    queue->confirmed_keys = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    return queue;
}

int latcd_retirement_queue_diagnostic_round(LatcdRetirementQueue *queue,
    const char *boot, uint64_t cutoff, const char *after)
{
    if (!queue || queue->cursor || queue->complete || !boot ||
        !g_uuid_string_is_valid(boot) || !cutoff ||
        (after && strlen(after) >= sizeof(queue->diagnostic_after))) return -1;
    g_strlcpy(queue->diagnostic_boot, boot, sizeof(queue->diagnostic_boot));
    g_strlcpy(queue->diagnostic_after, after ? after : "", sizeof(queue->diagnostic_after));
    queue->diagnostic_cutoff = cutoff;
    return 0;
}

int latcd_retirement_queue_diagnostic_resume(LatcdRetirementQueue *queue,
                                              char *error, size_t error_size)
{
    if (!queue || queue->cursor || queue->complete || queue->diagnostic_cutoff || queue->epoch)
        return fail(error, error_size, "retirement round resume requires a new queue");
    char *boot = NULL;
    uint64_t now = 0;
    LatcdRetirementPageState state;
    int result = -1;
    if (retirement_clock(&boot, &now) ||
        latcd_retirement_page_state_resume(queue->root, boot, queue->grace, now,
                                           &state, error, error_size) ||
        latcd_retirement_queue_diagnostic_round(queue, state.boot, state.round_cutoff,
                                                state.committed_pending ? state.cursor :
                                                                          state.committed_cursor)) goto out;
    result = 0;
out:
    g_free(boot);
    return result ? fail(error, error_size, "cannot resume retirement discovery round") : 0;
}

void latcd_retirement_queue_free(LatcdRetirementQueue *queue)
{
    if (!queue) return;
    if (queue->cursor) closedir(queue->cursor);
    if (queue->discovery_watch >= 0) close(queue->discovery_watch);
    if (queue->discovery_tombstones >= 0) close(queue->discovery_tombstones);
    latcd_recovery_close(queue->execution);
    g_hash_table_unref(queue->candidates);
    g_hash_table_unref(queue->discovered);
    g_hash_table_unref(queue->discovered_keys);
    g_hash_table_unref(queue->confirmed_keys);
    g_free(queue->root); g_free(queue);
}

unsigned latcd_retirement_queue_discovered_keys(const LatcdRetirementQueue *queue)
{
    return queue ? g_hash_table_size(queue->discovered_keys) : 0;
}

int latcd_retirement_queue_page_plan(const LatcdRetirementQueue *queue, const char *after,
                                     LatcdRetirementPageState *state)
{
    if (!queue || !state) return -1;
    GList *keys = g_hash_table_get_keys(queue->discovered_keys);
    keys = g_list_sort(keys, (GCompareFunc)strcmp);
    size_t count = g_list_length(keys);
    const char **names = g_new0(const char *, count);
    LatcdRetirementPageDeadline *schedule = g_new0(LatcdRetirementPageDeadline, count);
    unsigned i = 0;
    for (GList *item = keys; item; item = item->next, i++) {
        names[i] = item->data;
        g_strlcpy(schedule[i].name, item->data, sizeof(schedule[i].name));
        schedule[i].enqueued = 1;
        schedule[i].deadline = 1;
    }
    int result = latcd_retirement_page_plan(names, count, after, schedule, count, state);
    g_free(schedule); g_free(names); g_list_free(keys);
    return result;
}

int latcd_retirement_queue_aggregated_page(const LatcdRetirementQueue *queue,
                                          LatcdRetirementPageState *state)
{
    if (!queue || !state || queue->cursor || !queue->aggregation_verified) return -1;
    memset(state, 0, sizeof(*state));
    GList *keys = g_hash_table_get_keys(queue->discovered);
    keys = g_list_sort(keys, (GCompareFunc)strcmp);
    for (GList *item = keys; item; item = item->next) {
        RetirementCandidate *candidate = g_hash_table_lookup(queue->discovered, item->data);
        if (state->count == 128 || candidate->epoch != queue->epoch) {
            g_list_free(keys);
            memset(state, 0, sizeof(*state));
            return -1;
        }
        LatcdRetirementPageDeadline *entry = &state->entries[state->count++];
        g_strlcpy(entry->name, item->data, sizeof(entry->name));
        entry->deadline = candidate->deadline;
        entry->enqueued = candidate->enqueued;
    }
    if (state->count) g_strlcpy(state->cursor, state->entries[state->count - 1].name,
                                sizeof(state->cursor));
    g_list_free(keys);
    return 0;
}

static int queue_watch_fd(int notify, int fd, uint32_t mask)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    return inotify_add_watch(notify, path, mask) < 0 ? -1 : 0;
}

static bool queue_watch_clean(int notify)
{
    char buffer[4096];
    ssize_t count;
    do { count = read(notify, buffer, sizeof(buffer)); } while (count < 0 && errno == EINTR);
    return count < 0 && errno == EAGAIN;
}

static void queue_nominate(LatcdRetirementQueue *queue, const char *name)
{
    if (queue->diagnostic_cutoff && strcmp(name, queue->diagnostic_after) <= 0) return;
    if (g_hash_table_contains(queue->discovered_keys, name)) return;
    if (g_hash_table_size(queue->discovered_keys) == 128) {
        queue->discovery_overflow = true;
        const char *largest = NULL;
        GHashTableIter iterator;
        gpointer key;
        g_hash_table_iter_init(&iterator, queue->discovered_keys);
        while (g_hash_table_iter_next(&iterator, &key, NULL))
            if (!largest || strcmp(key, largest) > 0) largest = key;
        if (strcmp(name, largest) >= 0) return;
        g_hash_table_remove(queue->discovered_keys, largest);
    }
    g_hash_table_add(queue->discovered_keys, g_strdup(name));
}

static bool queue_outside_page(const LatcdRetirementQueue *queue, const char *name)
{
    if (queue->diagnostic_cutoff && strcmp(name, queue->diagnostic_after) <= 0)
        return true;
    if (!queue->discovery_overflow) return false;
    GHashTableIter iterator;
    gpointer key;
    const char *largest = NULL;
    g_hash_table_iter_init(&iterator, queue->discovered_keys);
    while (g_hash_table_iter_next(&iterator, &key, NULL))
        if (!largest || strcmp(key, largest) > 0) largest = key;
    return largest && strcmp(name, largest) > 0;
}

/* Completed namespace removal only, never physical-space or domain admission.
 * Bind the receipt to this transaction's object, not merely its basename. */
static int queue_object_removed(LatcdRetirementQueue *queue, const char *source,
                                 const char *name, GKeyFile *objects)
{
    int root = open(queue->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int store = queue->discovery_tombstones;
    int result = -1;
    char *raw = NULL, *stored_source = NULL, *hash = NULL;
    size_t size;
    GKeyFile *receipt = g_key_file_new();
    if (!queue_bind_root(queue, root) || store < 0) goto out;
    int fd = openat(store, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 && errno == ENOENT) { result = 0; goto out; }
    struct stat held, path;
    bool watched = fd >= 0 && !fstat(fd, &held) &&
        !queue_watch_fd(queue->discovery_watch, fd, IN_MODIFY | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF) &&
        !fstatat(store, name, &path, AT_SYMLINK_NOFOLLOW) && object_stat_equal(&held, &path);
    if (fd >= 0) close(fd);
    if (!watched) goto out;
    int status = read_file(store, name, RECORD_LIMIT, &raw, &size);
    if (status) { if (status == 1) result = 0; goto out; }
    uint64_t values[4];
    if (memchr(raw, 0, size) || !g_key_file_load_from_data(receipt, raw, size, 0, NULL) ||
        !tombstone_shape(receipt, name, &stored_source, values, &hash) ||
        g_strcmp0(source, stored_source)) goto out;
    if (!record_string_is(receipt, "tombstone", "deletion_status", "UNLINKED") ||
        !record_string_is(receipt, "tombstone", "recovery_status", "MISSING")) {
        result = 0;
        goto out;
    }
    struct stat st;
    if (!fstatat(root, name, &st, AT_SYMLINK_NOFOLLOW) || errno != ENOENT) goto out;
    int count = g_key_file_get_integer(objects, "objects", "count", NULL);
    const char *fields[] = {"device", "inode", "size", "allocated"};
    for (int i = 0; i < count; i++) {
        char group[32];
        snprintf(group, sizeof(group), "object%d", i);
        if (!record_string_is(objects, group, "name", name)) continue;
        bool matches = record_string_is(objects, group, "sha256", hash);
        for (unsigned j = 0; matches && j < G_N_ELEMENTS(fields); j++) {
            uint64_t value;
            matches = record_uint64(objects, group, fields[j], &value) && value == values[j];
        }
        if (matches) result = 1;
        break;
    }
out:
    g_free(raw); g_free(stored_source); g_free(hash); g_key_file_unref(receipt);
    if (root >= 0) close(root);
    return result;
}

static bool queue_record(LatcdRetirementQueue *queue, const char *raw, size_t size,
                          const char *boot, uint64_t now)
{
    GKeyFile *record = g_key_file_new();
    bool valid = !memchr(raw, 0, size) && g_key_file_load_from_data(record, raw, size, 0, NULL) &&
        record_shape_valid(record);
    char *source = g_key_file_get_string(record, "transaction", "source", NULL);
    char *state = g_key_file_get_string(record, "transaction", "state", NULL);
    valid = valid && source_valid(source) && state &&
        (!strcmp(state, "PREPARED") || !strcmp(state, "RETIRED") ||
         !strcmp(state, "ABORTED") || !strcmp(state, "UNKNOWN"));
    if (!valid || strcmp(state, "RETIRED")) goto out;
    char *old64 = g_key_file_get_string(record, "transaction", "previous", NULL);
    char *next64 = g_key_file_get_string(record, "transaction", "next", NULL);
    char *objects64 = g_key_file_get_string(record, "transaction", "objects", NULL);
    gsize old_size = 0, next_size = 0, object_size = 0;
    guchar *old = old64 ? decode_snapshot(old64, &old_size) : NULL;
    guchar *next = next64 ? decode_snapshot(next64, &next_size) : NULL;
    guchar *objects = objects64 ? g_base64_decode(objects64, &object_size) : NULL;
    char *canonical = objects ? g_base64_encode(objects, object_size) : NULL;
    uint64_t stamp;
    valid = record_string_is(record, "transaction", "version", "2") && old && next && objects &&
        canonical && !g_strcmp0(canonical, objects64) &&
        record_string_is(record, "transaction", "binding_status", "COMPLETE") &&
        record_string_is(record, "transaction", "objects_status", "RECORDED") &&
        !latcd_retirement_validate_binding(source, (char *)old, old_size, (char *)next, next_size,
                                          (char *)objects, object_size) &&
        record_string_is(record, "transaction", "retired_boot", boot) &&
        record_uint64(record, "transaction", "retired_boottime_us", &stamp) && stamp <= now &&
        queue->grace <= UINT64_MAX - stamp;
    GHashTable *old_refs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    GHashTable *next_refs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    valid = valid && (!old_size || manifest_references(source, (char *)old, old_size, old_refs)) &&
        manifest_references(source, (char *)next, next_size, next_refs);
    GHashTableIter iterator;
    gpointer key;
    g_hash_table_iter_init(&iterator, old_refs);
    GKeyFile *object_record = g_key_file_new();
    valid = valid && g_key_file_load_from_data(object_record, (char *)objects, object_size, 0, NULL);
    while (valid && g_hash_table_iter_next(&iterator, &key, NULL)) {
        if (g_hash_table_contains(next_refs, key)) continue;
        int removed = queue_object_removed(queue, source, key, object_record);
        if (removed < 0) { valid = false; break; }
        if (removed) continue;
        bool nominated = !queue->diagnostic_cutoff || stamp < queue->diagnostic_cutoff;
        if (!queue->aggregating && nominated) {
            queue_nominate(queue, key);
        } else if (queue->aggregating && nominated) {
            if (g_hash_table_contains(queue->discovered_keys, key))
                g_hash_table_add(queue->confirmed_keys, g_strdup(key));
            else if (!queue_outside_page(queue, key)) {
                valid = false;
                break;
            }
        }
        if (!queue->aggregating && !nominated) continue;
        RetirementCandidate *candidate = g_hash_table_lookup(queue->discovered, key);
        if (!candidate) {
            if (queue->aggregating) continue;
            if (g_hash_table_size(queue->discovered) >= 128) continue;
            candidate = g_new0(RetirementCandidate, 1);
            candidate->enqueued = now;
            g_hash_table_insert(queue->discovered, g_strdup(key), candidate);
        }
        uint64_t deadline = stamp + queue->grace;
        candidate->deadline = candidate->epoch == queue->epoch ? MAX(candidate->deadline, deadline) : deadline;
        candidate->epoch = queue->epoch;
    }
    g_key_file_unref(object_record);
    g_hash_table_unref(old_refs); g_hash_table_unref(next_refs);
    g_free(canonical); g_free(objects); g_free(next); g_free(old);
    g_free(objects64); g_free(next64); g_free(old64);
out:
    g_free(source); g_free(state); g_key_file_unref(record);
    return valid;
}

int latcd_retirement_queue_step(LatcdRetirementQueue *queue, unsigned entries,
                                 uint64_t time_us, LatcdRetirementQueueStats *stats,
                                 char *error, size_t error_size)
{
    if (!queue || !entries || !time_us || time_us > INT64_MAX / 2 || !stats)
        return fail(error, error_size, "invalid retirement queue budget");
    if (queue->execution)
        return fail(error, error_size, "cannot scan while retirement execution is active");
    memset(stats, 0, sizeof(*stats));
    if (queue->persistence_uncertain)
        return fail(error, error_size, "retirement scheduler requires reload");
    if (!queue->cursor) queue->aggregation_verified = false;
    int result = -1;
    char *boot = NULL;
    uint64_t now = 0;
    if (retirement_clock(&boot, &now)) goto out;
    if (queue->diagnostic_cutoff &&
        (strcmp(boot, queue->diagnostic_boot) || now < queue->diagnostic_cutoff ||
         (queue->cursor && now < queue->diagnostic_last_time))) goto out;
    if (queue->diagnostic_cutoff) queue->diagnostic_last_time = now;
    if (!queue->cursor) {
        queue->complete = false;
        queue->visited = 0;
        queue->aggregating = false;
        queue->aggregation_verified = false;
        queue->discovery_overflow = false;
        g_hash_table_remove_all(queue->discovered);
        g_hash_table_remove_all(queue->discovered_keys);
        g_hash_table_remove_all(queue->confirmed_keys);
        queue->epoch++;
        int root = open(queue->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (!queue_bind_root(queue, root)) { if (root >= 0) close(root); goto out; }
        int store = open_store(root, true);
        int gc = open_directory(root, ".gc", false);
        queue->discovery_tombstones = gc < 0 ? -1 : open_directory(gc, "tombstones", true);
        if (gc >= 0) close(gc);
        close(root);
        if (store < 0 || queue->discovery_tombstones < 0) { if (store >= 0) close(store); goto out; }
        queue->cursor = fdopendir(store);
        if (!queue->cursor) { close(store); goto out; }
        queue->discovery_watch = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (queue->discovery_watch < 0 || queue_watch_fd(queue->discovery_watch,
            dirfd(queue->cursor), IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO |
            IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR)) goto out;
        if (queue_watch_fd(queue->discovery_watch, queue->discovery_tombstones,
            IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_MODIFY |
            IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR) ||
            fstat(queue->discovery_tombstones, &queue->discovery_tombstone_store) ||
            fstat(dirfd(queue->cursor), &queue->discovery_store)) goto out;
    }
    int64_t started = g_get_monotonic_time();
    result = 1;
    while (stats->visited < entries && (uint64_t)(g_get_monotonic_time() - started) < time_us) {
        errno = 0;
        struct dirent *entry = readdir(queue->cursor);
        if (!entry) { result = errno ? -1 : 0; break; }
        stats->visited++;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char *raw = NULL;
        size_t size;
        int record_fd = openat(dirfd(queue->cursor), entry->d_name,
                               O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        struct stat watched, path;
        bool watched_ok = record_fd >= 0 && !fstat(record_fd, &watched) &&
            !queue_watch_fd(queue->discovery_watch, record_fd,
                IN_MODIFY | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF) &&
            !fstatat(dirfd(queue->cursor), entry->d_name, &path, AT_SYMLINK_NOFOLLOW) &&
            object_stat_equal(&watched, &path);
        if (record_fd >= 0) close(record_fd);
        bool valid = watched_ok && ++queue->visited <= 100000 && name_valid(entry->d_name) &&
            !read_file(dirfd(queue->cursor), entry->d_name, RECORD_LIMIT, &raw, &size) &&
            queue_record(queue, raw, size, boot, now);
        g_free(raw);
        if (!valid) { result = -1; break; }
    }
    if (!result && queue->cursor) {
        struct stat held, path;
        int root = open(queue->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        int store = root < 0 ? -1 : open_store(root, false);
        int gc = root < 0 ? -1 : open_directory(root, ".gc", false);
        int tombstones = gc < 0 ? -1 : open_directory(gc, "tombstones", false);
        struct stat held_tombstones, path_tombstones;
        if (!queue_bind_root(queue, root) || store < 0 || fstat(dirfd(queue->cursor), &held) || fstat(store, &path) ||
            !object_stat_equal(&queue->discovery_store, &held) ||
            !object_stat_equal(&held, &path) || tombstones < 0 ||
            fstat(queue->discovery_tombstones, &held_tombstones) || fstat(tombstones, &path_tombstones) ||
            !object_stat_equal(&queue->discovery_tombstone_store, &held_tombstones) ||
            !object_stat_equal(&held_tombstones, &path_tombstones) ||
            !queue_watch_clean(queue->discovery_watch)) result = -1;
        if (tombstones >= 0) close(tombstones);
        if (gc >= 0) close(gc);
        if (store >= 0) close(store);
        if (root >= 0) close(root);
    }
    if (!result && !queue->aggregating) {
        GList *keys = g_hash_table_get_keys(queue->discovered_keys);
        keys = g_list_sort(keys, (GCompareFunc)strcmp);
        g_hash_table_remove_all(queue->discovered);
        unsigned selected = 0;
        for (GList *item = keys; item && selected < 128; item = item->next) {
            if (queue->diagnostic_cutoff &&
                strcmp(item->data, queue->diagnostic_after) <= 0) continue;
            RetirementCandidate *candidate = g_new0(RetirementCandidate, 1);
            candidate->enqueued = now;
            g_hash_table_insert(queue->discovered, g_strdup(item->data), candidate);
            selected++;
        }
        g_list_free(keys);
        rewinddir(queue->cursor);
        queue->aggregating = true;
        queue->visited = 0;
        queue->epoch++;
        result = 1;
    }
    if (!result && g_hash_table_size(queue->discovered_keys) !=
                   g_hash_table_size(queue->confirmed_keys)) result = -1;
    if (!result) {
        GHashTableIter iterator;
        gpointer value;
        g_hash_table_iter_init(&iterator, queue->discovered);
        while (g_hash_table_iter_next(&iterator, NULL, &value)) {
            if (((RetirementCandidate *)value)->epoch != queue->epoch) {
                result = -1;
                break;
            }
        }
    }
    if (!result) queue->aggregation_verified = true;
    /* Diagnostic pages cannot feed the executor until durable page completion
     * and cross-page retry state are implemented. */
    if (!result && queue->diagnostic_cutoff) result = -1;
    if (!result && queue->discovery_overflow) result = -1;
    if (!result && *queue->active.name &&
        !g_hash_table_contains(queue->discovered, queue->active.name) &&
        g_hash_table_size(queue->discovered) >= 128) result = -1;
    if (!result) {
        GHashTableIter iterator;
        gpointer key, value;
        g_hash_table_iter_init(&iterator, queue->candidates);
        while (g_hash_table_iter_next(&iterator, &key, &value)) {
            RetirementCandidate *found = g_hash_table_lookup(queue->discovered, key);
            if (found && found->epoch == queue->epoch) {
                RetirementCandidate *old = value;
                found->enqueued = old->enqueued;
                found->last_attempt = old->last_attempt;
                found->retry_at = old->retry_at;
                found->busy_count = old->busy_count;
            } else if (!g_strcmp0(key, queue->active.name)) {
                RetirementCandidate *copy = g_memdup2(value, sizeof(RetirementCandidate));
                g_hash_table_insert(queue->discovered, g_strdup(key), copy);
            }
        }
        GHashTable *previous = queue->candidates;
        queue->candidates = queue->discovered;
        queue->discovered = previous;
        g_hash_table_remove_all(queue->discovered);
        g_hash_table_remove_all(queue->discovered_keys);
        g_hash_table_remove_all(queue->confirmed_keys);
        queue->complete = true;
    }
out:
    if (result <= 0 && queue->cursor) { closedir(queue->cursor); queue->cursor = NULL; }
    if (result <= 0 && queue->discovery_watch >= 0) {
        close(queue->discovery_watch);
        queue->discovery_watch = -1;
    }
    if (result <= 0 && queue->discovery_tombstones >= 0) {
        close(queue->discovery_tombstones);
        queue->discovery_tombstones = -1;
    }
    if (result < 0) queue->complete = false;
    stats->complete = queue->complete;
    stats->aggregating = result > 0 && queue->cursor && queue->aggregating;
    stats->candidates = g_hash_table_size(result > 0 ? queue->discovered : queue->candidates);
    GHashTableIter iterator;
    gpointer value;
    g_hash_table_iter_init(&iterator, queue->candidates);
    while (g_hash_table_iter_next(&iterator, NULL, &value)) {
        RetirementCandidate *candidate = value;
        if (!queue->complete) continue;
        uint64_t attempt = MAX(candidate->deadline, candidate->retry_at);
        if (attempt > now && (!stats->next_attempt_us || attempt < stats->next_attempt_us))
            stats->next_attempt_us = attempt;
        if (candidate->deadline <= now) {
            stats->due++;
            if (candidate->retry_at > now) stats->deferred++;
            else stats->ready++;
            uint64_t ready = MAX(candidate->deadline, candidate->enqueued);
            if (ready <= now) stats->oldest_due_wait_us = MAX(stats->oldest_due_wait_us, now - ready);
        } else if (!stats->next_deadline_us || candidate->deadline < stats->next_deadline_us)
            stats->next_deadline_us = candidate->deadline;
    }
    g_free(boot);
    return result < 0 ? fail(error, error_size, "retirement queue discovery incomplete or unsafe") : result;
}

int latcd_retirement_queue_take(LatcdRetirementQueue *queue, uint64_t now_us,
                                LatcdRetirementAttempt *attempt)
{
    if (!queue || !attempt || queue->persistence_uncertain || queue->active.sequence || queue->sequence == UINT64_MAX) return -1;
    memset(attempt, 0, sizeof(*attempt));
    if (!queue->complete) return 0;
    const char *after = NULL, *first = NULL;
    GHashTableIter iterator;
    gpointer key, value;
    g_hash_table_iter_init(&iterator, queue->candidates);
    while (g_hash_table_iter_next(&iterator, &key, &value)) {
        RetirementCandidate *candidate = value;
        if (candidate->deadline > now_us || candidate->retry_at > now_us) continue;
        if (!first || strncmp(key, first, 64) < 0) first = key;
        if (strncmp(key, queue->last_source, 64) > 0 && (!after || strncmp(key, after, 64) < 0)) after = key;
    }
    const char *source = after ? after : first, *selected = NULL;
    RetirementCandidate *oldest = NULL;
    if (!source) return 0;
    g_hash_table_iter_init(&iterator, queue->candidates);
    while (g_hash_table_iter_next(&iterator, &key, &value)) {
        RetirementCandidate *candidate = value;
        if (strncmp(key, source, 64) || candidate->deadline > now_us || candidate->retry_at > now_us) continue;
        if (!oldest || candidate->last_attempt < oldest->last_attempt ||
            (candidate->last_attempt == oldest->last_attempt &&
             (candidate->enqueued < oldest->enqueued ||
              (candidate->enqueued == oldest->enqueued && strcmp(key, selected) < 0)))) {
            selected = key; oldest = candidate;
        }
    }
    memcpy(queue->last_source, source, 64);
    queue->last_source[64] = 0;
    g_strlcpy(attempt->name, selected, sizeof(attempt->name));
    attempt->sequence = ++queue->sequence;
    oldest->last_attempt = attempt->sequence;
    queue->active = *attempt;
    return 1;
}

static int queue_checkpoint(LatcdRetirementQueue *queue, bool partial, bool active,
                             char *error, size_t error_size);

int latcd_retirement_queue_defer(LatcdRetirementQueue *queue,
                                 const LatcdRetirementAttempt *attempt,
                                 uint64_t now_us, bool busy)
{
    if (!queue || queue->persistence_uncertain || !attempt || !attempt->sequence ||
        attempt->sequence != queue->active.sequence ||
        memcmp(attempt->name, queue->active.name, sizeof(attempt->name))) return -1;
    RetirementCandidate *candidate = g_hash_table_lookup(queue->candidates, attempt->name);
    if (!candidate) return -1;
    candidate->busy_count = busy ? MIN(candidate->busy_count + 1, 7u) : 0;
    uint64_t delay = busy ? MIN(RETIREMENT_BUSY_MIN_US << (candidate->busy_count - 1),
                                RETIREMENT_BUSY_MAX_US) : 100000;
    candidate->retry_at = delay > UINT64_MAX - now_us ? UINT64_MAX : now_us + delay;
    if (candidate->epoch != queue->epoch) queue->complete = false;
    latcd_recovery_close(queue->execution);
    queue->execution = NULL;
    memset(&queue->active, 0, sizeof(queue->active));
    return 0;
}

int latcd_retirement_queue_defer_persist(LatcdRetirementQueue *queue,
    const LatcdRetirementAttempt *attempt, uint64_t now_us, bool busy,
    char *error, size_t error_size)
{
    if (!queue || !attempt || !attempt->sequence || queue->execution || queue->persistence_uncertain ||
        attempt->sequence != queue->active.sequence ||
        memcmp(attempt->name, queue->active.name, sizeof(attempt->name)) ||
        !queue->complete || queue->cursor || queue->diagnostic_cutoff)
        return fail(error, error_size, "invalid persistent retirement deferral");
    RetirementCandidate *candidate = g_hash_table_lookup(queue->candidates, attempt->name);
    if (!candidate || candidate->epoch != queue->epoch)
        return fail(error, error_size, "retirement candidate changed before deferral");
    char *boot = NULL;
    uint64_t observed;
    if (retirement_clock(&boot, &observed) || now_us > observed) {
        g_free(boot);
        return fail(error, error_size, "invalid retirement deferral clock");
    }
    g_free(boot);
    unsigned old_busy = candidate->busy_count;
    uint64_t old_retry = candidate->retry_at;
    candidate->busy_count = busy ? MIN(old_busy + 1, 7u) : 0;
    uint64_t delay = busy ? MIN(RETIREMENT_BUSY_MIN_US << (candidate->busy_count - 1),
                                RETIREMENT_BUSY_MAX_US) : 100000;
    if (delay > UINT64_MAX - now_us || observed - now_us >= delay) {
        candidate->busy_count = old_busy;
        return fail(error, error_size, "retirement deferral clock stale or overflowed");
    }
    candidate->retry_at = now_us + delay;
    if (queue_checkpoint(queue, false, true, error, error_size)) {
        candidate->busy_count = old_busy;
        candidate->retry_at = old_retry;
        queue->persistence_uncertain = true;
        return -1;
    }
    memset(&queue->active, 0, sizeof(queue->active));
    return 0;
}

static int execution_defer_persist(LatcdRetirementQueue *queue, uint64_t now,
                                   bool busy, char *error, size_t error_size)
{
    LatcdRetirementAttempt attempt = queue->active;
    latcd_recovery_close(queue->execution);
    queue->execution = NULL;
    if (latcd_retirement_queue_defer_persist(queue, &attempt, now, busy,
                                             error, error_size)) {
        queue->persistence_uncertain = true;
        return -1;
    }
    return 0;
}

int latcd_retirement_queue_execute_step(LatcdRetirementQueue *queue,
    uint64_t hash_bytes, uint64_t time_us, uint64_t *hashed_bytes,
    LatcdRetirementDeletionReport *report, char *error, size_t error_size)
{
    if (report) memset(report, 0, sizeof(*report));
    if (hashed_bytes) *hashed_bytes = 0;
    if (!queue || !hash_bytes || !time_us ||
        time_us > INT64_MAX - (uint64_t)g_get_monotonic_time())
        return fail(error, error_size, "invalid retirement consumer budget");
    int checked_root = open(queue->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    bool root_valid = queue_bind_root(queue, checked_root);
    if (checked_root >= 0) close(checked_root);
    if (!root_valid || queue->persistence_uncertain) {
        latcd_recovery_close(queue->execution);
        queue->execution = NULL;
        return fail(error, error_size, "retirement consumer root requires reload");
    }
    char *boot = NULL;
    uint64_t now;
    if (retirement_clock(&boot, &now)) {
        if (queue->execution) {
            latcd_recovery_close(queue->execution);
            queue->execution = NULL;
            queue->persistence_uncertain = true;
        }
        return fail(error, error_size, "cannot read retirement consumer clock");
    }
    g_free(boot);
    if (!queue->execution) {
        LatcdRetirementAttempt selected_attempt;
        int selected = latcd_retirement_queue_take(queue, now, &selected_attempt);
        if (selected <= 0) return selected;
        queue->execution = latcd_recovery_open(queue->root, true, error, error_size);
        queue->execution_started = now;
        if (!queue->execution) {
            if (execution_defer_persist(queue, now, true, error, error_size))
                return fail(error, error_size, "cannot defer retirement consumer after recovery open failure");
            return -1;
        }
    }
    LatcdRetirementAttempt attempt = queue->active;
    LatcdRecoveryCursor *cursor = queue->execution;
    cursor->bytes_left = hash_bytes;
    cursor->deadline = g_get_monotonic_time() + time_us;
    cursor->yielded = false;
    uint64_t before_bytes = cursor->progress.hashed_bytes;
    char source[65];
    memcpy(source, attempt.name, 64); source[64] = 0;
    int root = open(queue->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = root < 0 ? -1 : open_directory(root, ".gc", false);
    int store = gc < 0 ? -1 : open_directory(gc, "tombstones", false);
    int object = -1, latch = -1, result = -1;
    char *evidence = NULL;
    struct stat status;
    bool existing = false;
    if (!queue_bind_root(queue, root) || gc < 0) goto out;
    if (store >= 0) {
        if (!fstatat(store, attempt.name, &status, AT_SYMLINK_NOFOLLOW)) existing = true;
        else if (errno != ENOENT) goto out;
    } else if (errno != ENOENT) goto out;
    if (!existing) {
        object = openat(root, attempt.name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (object < 0 || flock(object, LOCK_SH | LOCK_NB)) goto out;
        evidence = recovery_capture(root, source, attempt.name, cursor);
        if (cursor->yielded) { result = 2; goto out; }
        if (!evidence) goto out;
        latch = lat_aot_v2_cache_source_lock(queue->root, source, LOCK_EX | LOCK_NB,
                                             false, error, error_size);
        if (latch < 0 || fstat(object, &status) ||
            object_transaction_status(root, attempt.name, &status, &queue->grace) ||
            retirement_tombstone(queue->root, source, attempt.name, object,
                                 evidence, latch, error, error_size)) goto out;
    }
    if (object >= 0) { close(object); object = -1; }
    if (latch >= 0) { close(latch); latch = -1; }
    result = tombstone_delete_cursor(queue->root, attempt.name, &queue->grace,
                                     cursor, report, error, error_size);
    if (result == 1 && cursor->yielded) result = 2;
out:
    if (object >= 0) close(object);
    if (latch >= 0) close(latch);
    if (store >= 0) close(store);
    if (gc >= 0) close(gc);
    if (root >= 0) close(root);
    g_free(evidence);
    if (hashed_bytes) *hashed_bytes = cursor->progress.hashed_bytes - before_bytes;
    if (result == 2) return 2;
    if (!result && record_write_fault("before-scheduler-checkpoint")) {
        latcd_recovery_close(queue->execution);
        queue->execution = NULL;
        queue->persistence_uncertain = true;
        return fail(error, error_size, "retirement scheduler checkpoint interrupted");
    }
    boot = NULL;
    uint64_t completed;
    if (record_write_fault("completion-clock") || retirement_clock(&boot, &completed)) {
        g_free(boot);
        latcd_recovery_close(queue->execution);
        queue->execution = NULL;
        queue->persistence_uncertain = true;
        return fail(error, error_size, "cannot read retirement completion clock");
    }
    g_free(boot);
    if (execution_defer_persist(queue, completed, result != 0, error, error_size))
        return fail(error, error_size, "cannot defer retirement consumer attempt");
    return result ? fail(error, error_size, "retirement consumer deferred or rejected") : 1;
}

int latcd_retirement_queue_execute_one(LatcdRetirementQueue *queue,
    LatcdRetirementDeletionReport *report, char *error, size_t error_size)
{
    int result;
    do {
        result = latcd_retirement_queue_execute_step(queue, UINT64_MAX, 1000000,
                                                     NULL, report, error, error_size);
    } while (result == 2);
    return result;
}

int latcd_retirement_queue_cancel(LatcdRetirementQueue *queue,
                                  char *error, size_t error_size)
{
    if (!queue) return fail(error, error_size, "invalid retirement consumer queue");
    if (queue->persistence_uncertain)
        return fail(error, error_size, "retirement scheduler requires reload");
    if (!queue->execution) return 0;
    char *boot = NULL;
    uint64_t now = queue->execution_started;
    if (retirement_clock(&boot, &now)) {
        latcd_recovery_close(queue->execution);
        queue->execution = NULL;
        queue->persistence_uncertain = true;
        g_free(boot);
        return fail(error, error_size, "cannot read retirement cancellation clock");
    }
    g_free(boot);
    return execution_defer_persist(queue, now, true, error, error_size);
}

static int queue_checkpoint(LatcdRetirementQueue *queue, bool partial, bool active,
                             char *error, size_t error_size)
{
    if (!queue || queue->persistence_uncertain || (!partial && (!queue->complete || queue->cursor)) ||
        queue->execution || (!active && *queue->active.name) ||
        g_hash_table_size(queue->candidates) > 128)
        return fail(error, error_size, "cannot checkpoint incomplete retirement discovery");
    int root = open(queue->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = !queue_bind_root(queue, root) ? -1 : open_directory(root, ".gc", true);
    GKeyFile *record = g_key_file_new();
    struct stat cache;
    char *boot = NULL;
    uint64_t now;
    int result = -1;
    if (gc < 0 || fstat(root, &cache) || retirement_clock(&boot, &now)) goto out;
    g_key_file_set_integer(record, "queue", "version", 1);
    g_key_file_set_string(record, "queue", "boot", boot);
    g_key_file_set_uint64(record, "queue", "cache_device", cache.st_dev);
    g_key_file_set_uint64(record, "queue", "cache_inode", cache.st_ino);
    g_key_file_set_uint64(record, "queue", "grace_us", queue->grace);
    g_key_file_set_uint64(record, "queue", "sequence", queue->sequence);
    g_key_file_set_string(record, "queue", "last_source", queue->last_source);
    GList *names = g_hash_table_get_keys(queue->candidates);
    names = g_list_sort(names, (GCompareFunc)strcmp);
    for (GList *item = names; item; item = item->next) {
        const char *name = item->data;
        RetirementCandidate *candidate = g_hash_table_lookup(queue->candidates, name);
        g_key_file_set_uint64(record, name, "enqueued", candidate->enqueued);
        g_key_file_set_uint64(record, name, "last_attempt", candidate->last_attempt);
        g_key_file_set_uint64(record, name, "retry_at", candidate->retry_at);
        g_key_file_set_uint64(record, name, "busy_count", candidate->busy_count);
    }
    g_list_free(names);
    char *previous = NULL;
    size_t previous_size;
    int status = read_file(gc, "retirement-scheduler.ini", RECORD_LIMIT, &previous, &previous_size);
    gsize current_size;
    char *current = g_key_file_to_data(record, &current_size, NULL);
    result = status < 0 || current_size > RECORD_LIMIT ? -1 : !active && !status && previous_size == current_size &&
        !memcmp(previous, current, current_size) ? 0 : write_record_kind(gc, "retirement-scheduler.ini", record, true, false, false, NULL, NULL);
    g_free(previous); g_free(current);
out:
    g_free(boot); g_key_file_unref(record);
    if (gc >= 0) close(gc);
    if (root >= 0) close(root);
    return result ? fail(error, error_size, "cannot persist retirement scheduler") : 0;
}

int latcd_retirement_queue_checkpoint(LatcdRetirementQueue *queue,
                                      char *error, size_t error_size)
{
    return queue_checkpoint(queue, false, false, error, error_size);
}

int latcd_retirement_queue_handoff(LatcdRetirementQueue *queue, const char *reason,
                                   char *error, size_t error_size)
{
    if (!queue || !reason || (strcmp(reason, "IDLE") && strcmp(reason, "STOP")))
        return fail(error, error_size, "invalid retirement handoff");
    char *boot = NULL;
    uint64_t now;
    if (retirement_clock(&boot, &now))
        return fail(error, error_size, "cannot timestamp retirement handoff");
    int result = -1, root = -1, gc = -1;
    GKeyFile *record = g_key_file_new();
    struct stat cache;
    if (latcd_retirement_queue_cancel(queue, error, error_size) ||
        (*queue->active.name && latcd_retirement_queue_defer(queue, &queue->active, now, true)) ||
        queue_checkpoint(queue, true, false, error, error_size)) goto out;
    root = open(queue->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    gc = !queue_bind_root(queue, root) ? -1 : open_directory(root, ".gc", false);
    if (gc < 0 || fstat(root, &cache)) goto out;
    g_key_file_set_integer(record, "handoff", "version", 1);
    g_key_file_set_string(record, "handoff", "boot", boot);
    g_key_file_set_uint64(record, "handoff", "cache_device", cache.st_dev);
    g_key_file_set_uint64(record, "handoff", "cache_inode", cache.st_ino);
    g_key_file_set_uint64(record, "handoff", "recorded_boottime_us", now);
    g_key_file_set_uint64(record, "handoff", "grace_us", queue->grace);
    g_key_file_set_string(record, "handoff", "reason", reason);
    g_key_file_set_string(record, "handoff", "state", "PENDING_RESCAN");
    g_key_file_set_boolean(record, "handoff", "discovery_complete", queue->complete);
    g_key_file_set_boolean(record, "handoff", "unattended_gc_guaranteed", false);
    g_key_file_set_boolean(record, "handoff", "automatic_deletion_enabled", false);
    g_key_file_set_uint64(record, "handoff", "known_candidates", g_hash_table_size(queue->candidates));
    uint64_t deferred = 0;
    GHashTableIter iterator;
    gpointer value;
    g_hash_table_iter_init(&iterator, queue->candidates);
    while (g_hash_table_iter_next(&iterator, NULL, &value))
        if (((RetirementCandidate *)value)->retry_at > now) deferred++;
    g_key_file_set_uint64(record, "handoff", "known_deferred", deferred);
    char *previous = NULL;
    size_t size;
    int status = read_file(gc, "retirement-handoff.ini", RECORD_LIMIT, &previous, &size);
    g_free(previous);
    if (status < 0) goto out;
    result = write_record_kind(gc, "retirement-handoff.ini", record, true, false, false, NULL, NULL);
out:
    if (gc >= 0) close(gc);
    if (root >= 0) close(root);
    g_key_file_unref(record);
    g_free(boot);
    return result ? fail(error, error_size, "cannot persist retirement exit handoff") : 0;
}

int latcd_retirement_queue_restore(LatcdRetirementQueue *queue,
                                   char *error, size_t error_size)
{
    if (!queue || queue->epoch || queue->cursor || g_hash_table_size(queue->candidates))
        return fail(error, error_size, "retirement scheduler restore requires a new queue");
    int root = open(queue->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = !queue_bind_root(queue, root) ? -1 : open_directory(root, ".gc", false);
    int result = -1;
    char *raw = NULL, *boot = NULL;
    size_t size;
    uint64_t now;
    struct stat cache;
    GKeyFile *record = g_key_file_new();
    GHashTable *restored = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    if (root < 0 || !queue_bind_root(queue, root)) goto out;
    if (gc < 0) { if (errno == ENOENT) result = 0; goto out; }
    int status = read_file(gc, "retirement-scheduler.ini", RECORD_LIMIT, &raw, &size);
    if (status) { if (status == 1) result = 0; goto out; }
    if (fstat(root, &cache) || retirement_clock(&boot, &now) || memchr(raw, 0, size) ||
        !g_key_file_load_from_data(record, raw, size, 0, NULL)) goto out;
    const char *keys[] = {"version", "boot", "cache_device", "cache_inode", "grace_us", "sequence", "last_source"};
    uint64_t device, inode, grace, sequence;
    char *saved_boot = g_key_file_get_string(record, "queue", "boot", NULL);
    char *last_source = g_key_file_get_string(record, "queue", "last_source", NULL);
    bool valid = exact_keys(record, "queue", keys, G_N_ELEMENTS(keys)) &&
        record_string_is(record, "queue", "version", "1") && hold_id_valid(saved_boot) &&
        last_source && (!*last_source || source_valid(last_source)) &&
        record_uint64(record, "queue", "cache_device", &device) && device == (uint64_t)cache.st_dev &&
        record_uint64(record, "queue", "cache_inode", &inode) && inode == (uint64_t)cache.st_ino &&
        record_uint64(record, "queue", "grace_us", &grace) &&
        record_uint64(record, "queue", "sequence", &sequence) && sequence < UINT64_MAX;
    bool compatible = valid && !strcmp(boot, saved_boot) && grace == queue->grace;
    gsize count;
    char **groups = g_key_file_get_groups(record, &count);
    valid &= count <= 129;
    const char *fields[] = {"enqueued", "last_attempt", "retry_at", "busy_count"};
    for (gsize i = 0; valid && i < count; i++) {
        const char *name = groups[i];
        if (!strcmp(name, "queue")) continue;
        char source[65] = {0};
        if (strlen(name) >= 64) memcpy(source, name, 64);
        uint64_t enqueued, attempted, retry, busy;
        valid = source_valid(source) && object_name_valid(source, name) &&
            exact_keys(record, name, fields, G_N_ELEMENTS(fields)) &&
            record_uint64(record, name, "enqueued", &enqueued) &&
            record_uint64(record, name, "last_attempt", &attempted) && attempted <= sequence &&
            record_uint64(record, name, "retry_at", &retry) &&
            record_uint64(record, name, "busy_count", &busy) && busy <= 7;
        if (compatible) valid = valid && enqueued <= now &&
            (retry <= now || retry - now <= RETIREMENT_BUSY_MAX_US);
        if (valid && compatible) {
            RetirementCandidate *candidate = g_new0(RetirementCandidate, 1);
            candidate->enqueued = enqueued;
            candidate->last_attempt = attempted;
            candidate->retry_at = retry;
            candidate->busy_count = busy;
            g_hash_table_insert(restored, g_strdup(name), candidate);
        }
    }
    g_strfreev(groups);
    if (valid) {
        if (compatible) {
            g_hash_table_unref(queue->candidates);
            queue->candidates = restored;
            restored = NULL;
            queue->sequence = sequence;
            g_strlcpy(queue->last_source, last_source, sizeof(queue->last_source));
        }
        result = 0;
    }
    g_free(last_source); g_free(saved_boot);
out:
    if (restored) g_hash_table_unref(restored);
    g_free(boot); g_free(raw); g_key_file_unref(record);
    if (gc >= 0) close(gc);
    if (root >= 0) close(root);
    return result ? fail(error, error_size, "retirement scheduler state unsafe or incompatible") : 0;
}

static void recovery_object_free(gpointer pointer)
{
    RecoveryObject *object = pointer;
    g_free(object->evidence);
    g_free(object);
}

static void recovery_hash_clear(LatcdRecoveryCursor *cursor)
{
    if (cursor->hash_fd >= 0) close(cursor->hash_fd);
    cursor->hash_fd = -1;
    g_clear_pointer(&cursor->hash_name, g_free);
    g_clear_pointer(&cursor->hash, g_checksum_free);
    cursor->offset = 0;
}

static char *recovery_capture(int root, const char *source, const char *name,
                              LatcdRecoveryCursor *cursor)
{
    if (!source_valid(source) || !object_name_valid(source, name)) return NULL;
    struct stat path, after;
    RecoveryObject *cached = g_hash_table_lookup(cursor->verified, name);
    if (cached) {
        return !fstatat(root, name, &path, AT_SYMLINK_NOFOLLOW) &&
            object_stat_equal(&path, &cached->identity) ? g_strdup(cached->evidence) : NULL;
    }
    if (cursor->hash_fd >= 0 && g_strcmp0(cursor->hash_name, name)) {
        recovery_hash_clear(cursor);
        return NULL;
    }
    if (cursor->hash_fd < 0) {
        cursor->hash_fd = openat(root, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (cursor->hash_fd < 0 || flock(cursor->hash_fd, LOCK_SH | LOCK_NB) ||
            fstat(cursor->hash_fd, &cursor->hash_identity) ||
            !S_ISREG(cursor->hash_identity.st_mode) || cursor->hash_identity.st_uid != geteuid() ||
            cursor->hash_identity.st_nlink != 1 || cursor->hash_identity.st_mode & 0222 ||
            cursor->hash_identity.st_size <= 0) goto invalid;
        cursor->hash_name = g_strdup(name);
        cursor->hash = g_checksum_new(G_CHECKSUM_SHA256);
    }
    if (fstat(cursor->hash_fd, &after) || !object_stat_equal(&after, &cursor->hash_identity) ||
        fstatat(root, name, &path, AT_SYMLINK_NOFOLLOW) ||
        !object_stat_equal(&path, &cursor->hash_identity)) goto invalid;
    while (cursor->offset < (uint64_t)cursor->hash_identity.st_size) {
        if (!cursor->bytes_left || g_get_monotonic_time() >= cursor->deadline) {
            cursor->yielded = true;
            return NULL;
        }
        unsigned char buffer[65536];
        size_t length = MIN((uint64_t)sizeof(buffer), cursor->bytes_left);
        length = MIN(length, (uint64_t)cursor->hash_identity.st_size - cursor->offset);
        ssize_t count = read(cursor->hash_fd, buffer, length);
        if (count < 0 && errno == EINTR) {
            cursor->yielded = true;
            return NULL;
        }
        if (count <= 0) goto invalid;
        cursor->offset += count;
        cursor->bytes_left -= count;
        cursor->progress.hashed_bytes += count;
        g_checksum_update(cursor->hash, buffer, count);
    }
    if (fstat(cursor->hash_fd, &after) || !object_stat_equal(&after, &cursor->hash_identity) ||
        fstatat(root, name, &path, AT_SYMLINK_NOFOLLOW) ||
        !object_stat_equal(&path, &cursor->hash_identity)) goto invalid;
    GKeyFile *record = g_key_file_new();
    g_key_file_set_integer(record, "objects", "count", 1);
    g_key_file_set_string(record, "object0", "name", name);
    g_key_file_set_uint64(record, "object0", "device", after.st_dev);
    g_key_file_set_uint64(record, "object0", "inode", after.st_ino);
    g_key_file_set_uint64(record, "object0", "size", after.st_size);
    g_key_file_set_uint64(record, "object0", "allocated", (uint64_t)after.st_blocks * 512);
    g_key_file_set_string(record, "object0", "sha256", g_checksum_get_string(cursor->hash));
    RecoveryObject *object = g_new0(RecoveryObject, 1);
    object->identity = after;
    object->evidence = g_key_file_to_data(record, NULL, NULL);
    g_key_file_unref(record);
    g_hash_table_insert(cursor->verified, g_strdup(name), object);
    recovery_hash_clear(cursor);
    return g_strdup(object->evidence);
invalid:
    recovery_hash_clear(cursor);
    return NULL;
}

void latcd_recovery_close(LatcdRecoveryCursor *cursor)
{
    if (!cursor) return;
    recovery_hash_clear(cursor);
    if (cursor->directory) closedir(cursor->directory);
    if (cursor->root >= 0) close(cursor->root);
    g_hash_table_unref(cursor->verified);
    g_free(cursor->root_path); g_free(cursor->pending); g_free(cursor);
}

LatcdRecoveryCursor *latcd_recovery_open(const char *root, bool tombstones,
                                        char *error, size_t error_size)
{
    LatcdRecoveryCursor *cursor = g_new0(LatcdRecoveryCursor, 1);
    cursor->root = -1;
    cursor->hash_fd = -1;
    cursor->tombstones = tombstones;
    cursor->root_path = g_strdup(root);
    cursor->verified = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, recovery_object_free);
    cursor->root = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (cursor->root < 0) goto invalid;
    int gc = open_directory(cursor->root, ".gc", false);
    int store = gc < 0 ? -1 : open_directory(gc, tombstones ? "tombstones" : "transactions", false);
    int saved = errno;
    if (gc >= 0) close(gc);
    if (store < 0) {
        if (saved != ENOENT) goto invalid;
        cursor->done = true;
    } else {
        cursor->directory = fdopendir(store);
        if (!cursor->directory) { close(store); goto invalid; }
    }
    return cursor;
invalid:
    latcd_recovery_close(cursor);
    fail(error, error_size, "unsafe recovery store");
    return NULL;
}

int latcd_recovery_step(LatcdRecoveryCursor *cursor, unsigned entries,
                        uint64_t hash_bytes, uint64_t time_us,
                        LatcdRecoveryProgress *progress, char *error, size_t error_size)
{
    if (!cursor || !progress || !entries || !hash_bytes || !time_us ||
        time_us > INT64_MAX - (uint64_t)g_get_monotonic_time())
        return fail(error, error_size, "invalid recovery budget");
    *progress = cursor->progress;
    if (cursor->failed) return fail(error, error_size, "recovery cursor previously failed");
    if (cursor->done) return 0;
    int roots = -1;
    int gc = open_directory(cursor->root, ".gc", false);
    struct stat held_root, path_root, held_gc, path_gc, held_store, path_store;
    if (gc < 0 || fstat(cursor->root, &held_root) || lstat(cursor->root_path, &path_root) ||
        held_root.st_dev != path_root.st_dev || held_root.st_ino != path_root.st_ino ||
        fstat(gc, &held_gc) || fstatat(cursor->root, ".gc", &path_gc, AT_SYMLINK_NOFOLLOW) ||
        held_gc.st_dev != path_gc.st_dev || held_gc.st_ino != path_gc.st_ino ||
        fstat(dirfd(cursor->directory), &held_store) ||
        fstatat(gc, cursor->tombstones ? "tombstones" : "transactions", &path_store,
                AT_SYMLINK_NOFOLLOW) || held_store.st_dev != path_store.st_dev ||
        held_store.st_ino != path_store.st_ino) {
        if (gc >= 0) close(gc);
        cursor->failed = true;
        recovery_hash_clear(cursor);
        return fail(error, error_size, "recovery directory binding changed");
    }
    if (!cursor->tombstones) {
        roots = roots_lock_gc(gc, LOCK_SH | LOCK_NB, error, error_size);
        if (roots < 0) { close(gc); return -1; }
        if (lstat(cursor->root_path, &path_root) ||
            held_root.st_dev != path_root.st_dev || held_root.st_ino != path_root.st_ino ||
            !directory_matches_at(cursor->root, ".gc", gc) ||
            !directory_matches_at(gc, "transactions", dirfd(cursor->directory)) ||
            !lock_matches_at(gc, "reference-roots.lock", roots)) {
            close(roots);
            close(gc);
            cursor->failed = true;
            recovery_hash_clear(cursor);
            return fail(error, error_size, "recovery binding changed while acquiring latch");
        }
    }
    close(gc);
    cursor->bytes_left = hash_bytes;
    cursor->deadline = g_get_monotonic_time() + time_us;
    cursor->yielded = false;
    unsigned visited = 0;
    while (visited < entries && g_get_monotonic_time() < cursor->deadline) {
        if (!cursor->pending) {
            errno = 0;
            struct dirent *entry = readdir(cursor->directory);
            if (!entry) {
                if (errno) goto invalid;
                cursor->done = true;
                break;
            }
            visited++;
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            if (++cursor->progress.visited > 100000) goto invalid;
            if (g_str_has_prefix(entry->d_name, ".write-")) continue;
            cursor->pending = g_strdup(entry->d_name);
            if (fstatat(dirfd(cursor->directory), cursor->pending, &cursor->pending_identity,
                         AT_SYMLINK_NOFOLLOW)) goto invalid;
        } else visited++;
        struct stat record;
        if (fstatat(dirfd(cursor->directory), cursor->pending, &record, AT_SYMLINK_NOFOLLOW) ||
            !object_stat_equal(&record, &cursor->pending_identity)) goto invalid;
        int result = cursor->tombstones ? recover_tombstone(cursor->root_path, cursor->root,
            dirfd(cursor->directory), cursor->pending, false, cursor, NULL, NULL) :
            recover_record(cursor->root, dirfd(cursor->directory), cursor->pending, true, cursor);
        if (result < 0) goto invalid;
        if (result > 0) break;
        cursor->progress.recovered++;
        g_clear_pointer(&cursor->pending, g_free);
        g_hash_table_remove_all(cursor->verified);
        recovery_hash_clear(cursor);
    }
    *progress = cursor->progress;
    if (roots >= 0) close(roots);
    return cursor->done ? 0 : 1;
invalid:
    if (roots >= 0) close(roots);
    cursor->failed = true;
    recovery_hash_clear(cursor);
    *progress = cursor->progress;
    return fail(error, error_size, "recovery rejected unknown or changed record");
}
