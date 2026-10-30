#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../latcd/broker-source.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static bool cancelled(void *opaque) { return *(bool *)opaque; }

int main(int argc, char **argv)
{
    assert(argc == 2);
    char *data = NULL; gsize size = 0;
    assert(g_file_get_contents(argv[1], &data, &size, NULL));
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(sum, (const guchar *)data, size);
    uint8_t digest[32], verified[32]; gsize length = sizeof(digest);
    g_checksum_get_digest(sum, digest, &length); g_checksum_free(sum);
    int fd = memfd_create("broker-source-test", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(fd >= 0 && write(fd, data, size) == (ssize_t)size);
    char error[128];
    assert(latcd_broker_source_validate(fd, size, size, digest, verified, error, sizeof(error)) < 0);
    assert(!fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL));
    assert(!latcd_broker_source_validate(fd, size, size, digest, verified, error, sizeof(error)));
    assert(!memcmp(digest, verified, sizeof(digest)));
    bool stop = true;
    assert(latcd_broker_source_validate_bounded(fd, size, size, digest, verified,
        error, sizeof(error), 0, cancelled, &stop) < 0 && errno == ECANCELED);
    for (unsigned i = 0; i < sizeof(verified); i++) assert(!verified[i]);
    assert(latcd_broker_source_validate_bounded(fd, size, size, digest, verified,
        error, sizeof(error), g_get_monotonic_time() - 1, NULL, NULL) < 0 && errno == ECANCELED);
    stop = false;
    assert(!latcd_broker_source_validate_bounded(fd, size, size, digest, verified,
        error, sizeof(error), g_get_monotonic_time() + G_TIME_SPAN_SECOND, cancelled, &stop));
    memcpy(verified, digest, sizeof(digest));
    assert(!latcd_broker_source_validate(fd, size, size, verified, verified, error, sizeof(error)));
    assert(!memcmp(digest, verified, sizeof(digest)));
    assert(latcd_broker_source_validate(fd, size, size - 1, digest, verified, error, sizeof(error)) < 0);
    assert(latcd_broker_source_validate(fd, size - 1, size, digest, verified, error, sizeof(error)) < 0);
    int plain = open(argv[1], O_RDONLY | O_CLOEXEC);
    assert(plain >= 0);
    assert(latcd_broker_source_validate(plain, size, size, digest, verified, error, sizeof(error)) < 0);
    close(plain);
    int invalid = memfd_create("broker-source-invalid", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(invalid >= 0 && !ftruncate(invalid, size));
    assert(!fcntl(invalid, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL));
    assert(latcd_broker_source_validate(invalid, size, size, digest, verified, error, sizeof(error)) < 0);
    close(invalid);
    digest[0] ^= 1;
    assert(latcd_broker_source_validate(fd, size, size, digest, verified, error, sizeof(error)) < 0);
    for (unsigned i = 0; i < sizeof(verified); i++) assert(!verified[i]);
    close(fd); g_free(data);
    return 0;
}
