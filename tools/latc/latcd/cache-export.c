#define _GNU_SOURCE
#include "cache-export.h"

#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int latcd_cache_export_copy(int source, const char *sha256, uint64_t max_bytes)
{
    struct stat before, after;
    if (source < 0 || !sha256 || strlen(sha256) != 64 ||
        strspn(sha256, "0123456789abcdef") != 64 || !max_bytes ||
        fstat(source, &before) || !S_ISREG(before.st_mode) ||
        before.st_size <= 0 || (uint64_t)before.st_size > max_bytes ||
        before.st_uid != geteuid() || (before.st_mode & 0222)) {
        errno = EINVAL;
        return -1;
    }
    int output = memfd_create("latcd-module-export", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (output < 0) return -1;
    errno = 0;
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    unsigned char buffer[128 * 1024];
    off_t position = 0;
    bool valid = checksum != NULL;
    while (valid && position < before.st_size) {
        size_t wanted = MIN(sizeof(buffer), (uint64_t)(before.st_size - position));
        ssize_t count = pread(source, buffer, wanted, position);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { valid = false; break; }
        g_checksum_update(checksum, buffer, count);
        ssize_t offset = 0;
        while (offset < count) {
            ssize_t written = write(output, buffer + offset, count - offset);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) { valid = false; break; }
            offset += written;
        }
        position += count;
    }
    valid = valid && !fstat(source, &after) && before.st_dev == after.st_dev &&
        before.st_ino == after.st_ino && before.st_size == after.st_size &&
        before.st_mode == after.st_mode && before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
        before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        !strcmp(g_checksum_get_string(checksum), sha256) &&
        !fcntl(output, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
    if (checksum) g_checksum_free(checksum);
    if (!valid) { int saved = errno ? errno : EIO; close(output); errno = saved; return -1; }
    return output;
}
