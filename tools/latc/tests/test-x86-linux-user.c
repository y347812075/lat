#include "x86-linux-user.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

enum {
    ENV_RAX = 344,
    ENV_RSI = 392,
    ENV_RDI = 400,
};

static uint64_t *reg(unsigned char *env, size_t offset)
{
    return (void *)(env + offset);
}

int main(void)
{
    unsigned char env[1024] = {0};
    long page_size = sysconf(_SC_PAGESIZE);
    void *mapping = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    *reg(env, ENV_RAX) = 11;
    *reg(env, ENV_RDI) = (uintptr_t)mapping;
    *reg(env, ENV_RSI) = (uint64_t)page_size;
    lat_x86_linux_user_syscall(env);
    if (*reg(env, ENV_RAX) != 0) {
        fprintf(stderr, "x86 munmap returned %lld\n",
                (long long)*reg(env, ENV_RAX));
        return 1;
    }
    errno = 0;
    if (mprotect(mapping, (size_t)page_size, PROT_READ) == 0 ||
        errno != ENOMEM) {
        fprintf(stderr, "x86 munmap left the mapping present\n");
        return 1;
    }
    puts("test-x86-linux-user: PASS");
    return 0;
}
