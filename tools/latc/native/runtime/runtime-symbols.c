#define _GNU_SOURCE

#include "runtime-symbols.h"

#include "lat-native-image.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>

static const unsigned char placeholder_pftable[256];
static uint32_t configured_flags;

#if defined(__loongarch__)
static unsigned char *guest_brk_base;
static unsigned char *guest_brk_current;
static size_t guest_brk_capacity;

static uint64_t x86_result(long result)
{
    return result < 0 ? (uint64_t)-(int64_t)errno : (uint64_t)result;
}

static uint64_t x86_guest_brk(uint64_t requested)
{
    if (!guest_brk_base) {
        guest_brk_capacity = 16 * 1024 * 1024;
        guest_brk_base = mmap(NULL, guest_brk_capacity, PROT_NONE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (guest_brk_base == MAP_FAILED) {
            guest_brk_base = NULL;
            guest_brk_capacity = 0;
            return 0;
        }
        guest_brk_current = guest_brk_base;
    }
    if (!requested) return (uint64_t)(uintptr_t)guest_brk_current;
    if (requested < (uint64_t)(uintptr_t)guest_brk_base ||
        requested > (uint64_t)(uintptr_t)guest_brk_base + guest_brk_capacity) {
        return (uint64_t)(uintptr_t)guest_brk_current;
    }
    long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t end = (requested + (uint64_t)page_size - 1) &
                    ~((uint64_t)page_size - 1);
    if (end > (uintptr_t)guest_brk_base &&
        mprotect(guest_brk_base, end - (uintptr_t)guest_brk_base,
                 PROT_READ | PROT_WRITE)) {
        return (uint64_t)(uintptr_t)guest_brk_current;
    }
    guest_brk_current = (unsigned char *)(uintptr_t)requested;
    return requested;
}

extern void lat_native_x86_dispatch_jirl(void);

static void x86_exit_smoke_syscall(void)
{
    register unsigned char *env __asm__("$s8");
    uint64_t syscall_number = *(uint64_t *)(env + 344);
    uint64_t first_argument = *(uint64_t *)(env + 400);
    if (syscall_number == 60) {
        _exit((int)first_argument);
    }
    if (syscall_number == 1) {
        uint64_t second_argument = *(uint64_t *)(env + 392);
        uint64_t third_argument = *(uint64_t *)(env + 360);
        ssize_t result = write((int)first_argument,
                               (const void *)(uintptr_t)second_argument,
                               (size_t)third_argument);
        *(uint64_t *)(env + 344) = x86_result(result);
        return;
    }
    if (syscall_number == 0) {
        uint64_t second_argument = *(uint64_t *)(env + 392);
        uint64_t third_argument = *(uint64_t *)(env + 360);
        ssize_t result = read((int)first_argument,
                              (void *)(uintptr_t)second_argument,
                              (size_t)third_argument);
        *(uint64_t *)(env + 344) = x86_result(result);
        return;
    }
    if (syscall_number == 3) {
        int result = close((int)first_argument);
        *(uint64_t *)(env + 344) = x86_result(result);
        return;
    }
    if (syscall_number == 9) {
        uint64_t length = *(uint64_t *)(env + 392);
        int prot = (int)*(uint64_t *)(env + 360);
        int flags = (int)*(uint64_t *)(env + 424);
        int fd = (int)*(uint64_t *)(env + 408);
        uint64_t offset = *(uint64_t *)(env + 416);
        void *result = mmap((void *)(uintptr_t)first_argument, length, prot,
                            flags, fd, offset);
        *(uint64_t *)(env + 344) = result == MAP_FAILED ?
            x86_result(-1) : (uint64_t)(uintptr_t)result;
        return;
    }
    if (syscall_number == 12) {
        *(uint64_t *)(env + 344) = x86_guest_brk(first_argument);
        return;
    }
    if (syscall_number == 257) {
        const char *path = (const void *)(uintptr_t)
            *(uint64_t *)(env + 392);
        int flags = (int)*(uint64_t *)(env + 360);
        mode_t mode = (mode_t)*(uint64_t *)(env + 424);
        int result = openat((int)first_argument, path, flags, mode);
        *(uint64_t *)(env + 344) = x86_result(result);
        return;
    }
    _exit(127);
}
#endif

__attribute__((noreturn))
static void unsupported_runtime_entry(void)
{
    abort();
}

uintptr_t lat_runtime_symbol_address(uint32_t symbol)
{
    if (symbol == LAT_NATIVE_SYMBOL_PFTABLE) {
        return (uintptr_t)placeholder_pftable;
    }
#if defined(__loongarch__)
    if (symbol == LAT_NATIVE_SYMBOL_EPILOGUE_RET_0 &&
        (configured_flags & LAT_NATIVE_IMAGE_X86_EXIT_SMOKE)) {
        return (uintptr_t)lat_native_x86_dispatch_jirl;
    }
    if (symbol == LAT_NATIVE_SYMBOL_RAISE_SYSCALL &&
        (configured_flags & LAT_NATIVE_IMAGE_X86_EXIT_SMOKE)) {
        return (uintptr_t)x86_exit_smoke_syscall;
    }
#endif
    if (symbol > LAT_NATIVE_SYMBOL_INVALID &&
        symbol < LAT_NATIVE_SYMBOL_COUNT) {
        return (uintptr_t)unsupported_runtime_entry;
    }
    return 0;
}

void lat_runtime_symbols_configure(uint32_t image_flags)
{
    configured_flags = image_flags;
}
