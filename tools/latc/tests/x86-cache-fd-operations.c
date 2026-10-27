#define _GNU_SOURCE
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int transfer(int fd, void *data, size_t size, int writing)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t count = writing ? write(fd, (char *)data + offset, size - offset) :
                                  read(fd, (char *)data + offset, size - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        offset += count;
    }
    return 0;
}

int main(void)
{
    int64_t request[7], result;
    char buffer[4096];
    static const char attribute[] = "user.lat-gc-test";
    if (transfer(1, "READY\n", 6, 1)) return 1;
    while (!transfer(0, request, sizeof(request), 0)) {
        memset(buffer, 0, sizeof(buffer));
        if (request[0] == 72) {
            struct flock lock = { .l_type = F_RDLCK, .l_whence = SEEK_SET };
            memcpy(buffer, &lock, sizeof(lock));
            if (request[3] == -4) {
                lock.l_type = F_UNLCK;
                memcpy(buffer, &lock, sizeof(lock));
                request[3] = -1;
            }
        }
        for (int i = 2; i < 7; i++) {
            if (request[i] == -1) request[i] = (intptr_t)buffer;
            else if (request[i] == -2) request[i] = (intptr_t)attribute;
        }
        errno = 0;
        result = syscall(request[0], request[1], request[2], request[3],
                         request[4], request[5], request[6]);
        if (result == -1) result = -errno;
        if (transfer(1, &result, sizeof(result), 1)) return 2;
    }
    return 0;
}
