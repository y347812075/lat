#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "launch-options.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

bool latcd_launch_options_match(int fd, const GPtrArray *options)
{
    const int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    struct stat st;
    int seals = fcntl(fd, F_GET_SEALS);
    if (!options || seals < 0 || (seals & required) != required || fstat(fd, &st) ||
        !S_ISREG(st.st_mode) || st.st_size < 0) return false;
    off_t offset = 0;
    char buffer[4096];
    for (guint i = 0; i < options->len; i++) {
        const char *option = g_ptr_array_index(options, i);
        if (!option) return false;
        size_t length = strlen(option) + 1;
        for (size_t done = 0; done < length;) {
            size_t wanted = MIN(sizeof(buffer), length - done);
            ssize_t n = pread(fd, buffer, wanted, offset);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0 || memcmp(buffer, option + done, n)) return false;
            offset += n;
            done += n;
        }
    }
    return offset == st.st_size;
}
