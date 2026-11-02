#define _GNU_SOURCE
#include "../latcd/launch-options.h"
#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

static int make_options(const void *data, size_t size, bool sealed)
{
    int fd = memfd_create("test-launch-options", MFD_ALLOW_SEALING | MFD_CLOEXEC);
    assert(fd >= 0);
    assert(write(fd, data, size) == (ssize_t)size);
    if (sealed)
        assert(!fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW |
                      F_SEAL_SHRINK | F_SEAL_SEAL));
    return fd;
}

int main(void)
{
    const char encoded[] = "--setenv\0PATH\0/usr/bin\0";
    GPtrArray *options = g_ptr_array_new();
    g_ptr_array_add(options, "--setenv");
    g_ptr_array_add(options, "PATH");
    g_ptr_array_add(options, "/usr/bin");
    int fd = make_options(encoded, sizeof(encoded) - 1, true);
    assert(latcd_launch_options_match(fd, options));
    g_ptr_array_index(options, 1) = "PATS";
    assert(!latcd_launch_options_match(fd, options));
    g_ptr_array_index(options, 1) = "PATH";
    close(fd);
    fd = make_options(encoded, sizeof(encoded) - 2, true);
    assert(!latcd_launch_options_match(fd, options));
    close(fd);
    fd = make_options(encoded, sizeof(encoded), true);
    assert(!latcd_launch_options_match(fd, options));
    close(fd);
    fd = make_options(encoded, sizeof(encoded) - 1, false);
    assert(!latcd_launch_options_match(fd, options));
    close(fd);
    g_ptr_array_free(options, TRUE);
    return 0;
}
