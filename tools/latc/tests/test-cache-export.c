#define _GNU_SOURCE
#include "../latcd/cache-export.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    int source = memfd_create("export-source", MFD_CLOEXEC);
    assert(source >= 0 && write(source, "abc", 3) == 3 && !fchmod(source, 0400));
    char *digest = g_compute_checksum_for_string(G_CHECKSUM_SHA256, "abc", 3);
    assert(latcd_cache_export_copy(source, digest, 2) < 0);
    int copy = latcd_cache_export_copy(source, digest, 3);
    assert(copy >= 0 && (fcntl(copy, F_GET_SEALS) &
        (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) ==
        (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL));
    char data[3];
    assert(pread(copy, data, sizeof(data), 0) == 3 && !memcmp(data, "abc", 3));
    assert(pwrite(copy, "x", 1, 0) < 0 && errno == EPERM);
    assert(pwrite(source, "x", 1, 0) == 1);
    assert(pread(copy, data, sizeof(data), 0) == 3 && !memcmp(data, "abc", 3));
    digest[0] = digest[0] == '0' ? '1' : '0';
    assert(latcd_cache_export_copy(source, digest, 3) < 0);
    g_free(digest); close(copy); close(source);
    return 0;
}
