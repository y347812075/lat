#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "broker-source.h"
#include "source-elf.h"
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int latcd_broker_source_validate(int fd, uint64_t size, uint64_t limit,
                                 const uint8_t claimed[32], uint8_t verified[32],
                                 char *error, size_t error_size)
{
    uint8_t expected[32];
    if (claimed) memcpy(expected, claimed, sizeof(expected));
    if (verified) memset(verified, 0, 32);
    struct stat st;
    const int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    int seals = fd < 0 ? -1 : fcntl(fd, F_GET_SEALS);
    if (!claimed || !verified || !size || size > limit || seals < 0 ||
        (seals & required) != required || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || (uint64_t)st.st_size != size ||
        latcd_validate_x86_elf(fd, size, error, error_size)) {
        errno = EINVAL;
        return -1;
    }
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    if (!sum) { errno = ENOMEM; return -1; }
    unsigned char buffer[128 * 1024], digest[32];
    uint64_t offset = 0;
    while (offset < size) {
        size_t wanted = MIN(sizeof(buffer), size - offset);
        ssize_t count = pread(fd, buffer, wanted, offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { g_checksum_free(sum); errno = EIO; return -1; }
        g_checksum_update(sum, buffer, count);
        offset += count;
    }
    gsize length = sizeof(digest);
    g_checksum_get_digest(sum, digest, &length);
    g_checksum_free(sum);
    if (length != sizeof(digest) || memcmp(digest, expected, sizeof(digest))) {
        errno = EINVAL;
        return -1;
    }
    memcpy(verified, digest, sizeof(digest));
    return 0;
}
