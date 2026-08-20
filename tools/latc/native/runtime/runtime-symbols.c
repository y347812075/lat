#define _GNU_SOURCE

#include "runtime-symbols.h"

#include "lat-native-image.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>

static const unsigned char placeholder_pftable[256];
static uint32_t configured_flags;

#if defined(__loongarch__)
static unsigned char *guest_brk_base;
static unsigned char *guest_brk_current;
static size_t guest_brk_capacity;
static uint64_t guest_clear_tid;

enum {
    LAT_ENV_EFLAGS_OFFSET = 480,
    LAT_ENV_XMM0_OFFSET = 1176,
    LAT_ENV_RCX_OFFSET = 352,
    LAT_ENV_FS_BASE_OFFSET = 632,
    LAT_ENV_GS_BASE_OFFSET = 656,
};

typedef union LatXmm128 {
    uint8_t b[16];
    uint16_t w[8];
    uint64_t q[2];
} LatXmm128;

enum {
    X86_CC_C = 0x0001,
    X86_CC_P = 0x0004,
    X86_CC_A = 0x0010,
    X86_CC_Z = 0x0040,
    X86_CC_S = 0x0080,
    X86_CC_O = 0x0800,
};

static int pcmp_ilen(const LatXmm128 *value, uint8_t control)
{
    int length = 0;
    if (control & 1) {
        while (length < 8 && value->w[length]) length++;
    } else {
        while (length < 16 && value->b[length]) length++;
    }
    return length;
}

static int pcmp_value(const LatXmm128 *value, uint8_t control, int index)
{
    switch (control & 3) {
    case 0: return value->b[index];
    case 1: return value->w[index];
    case 2: return (int8_t)value->b[index];
    default: return (int16_t)value->w[index];
    }
}

static unsigned pcmp_result(unsigned char *env, const LatXmm128 *d,
                            const LatXmm128 *s, uint8_t control)
{
    int valid_s = pcmp_ilen(s, control) - 1;
    int valid_d = pcmp_ilen(d, control) - 1;
    int upper = (control & 1) ? 7 : 15;
    unsigned result = 0;
    uint64_t *eflags = (void *)(env + LAT_ENV_EFLAGS_OFFSET);

    if (valid_s < upper) *eflags |= X86_CC_Z;
    else *eflags &= ~X86_CC_Z;
    if (valid_d < upper) *eflags |= X86_CC_S;
    else *eflags &= ~X86_CC_S;

    switch ((control >> 2) & 3) {
    case 0:
        for (int j = valid_s; j >= 0; j--) {
            result <<= 1;
            int value = pcmp_value(s, control, j);
            for (int i = valid_d; i >= 0; i--) {
                result |= value == pcmp_value(d, control, i);
            }
        }
        break;
    case 1:
        for (int j = valid_s; j >= 0; j--) {
            result <<= 1;
            int value = pcmp_value(s, control, j);
            for (int i = ((valid_d - 1) | 1); i >= 0; i -= 2) {
                result |= pcmp_value(d, control, i) >= value &&
                          pcmp_value(d, control, i - 1) <= value;
            }
        }
        break;
    case 2: {
        int maximum = valid_s > valid_d ? valid_s : valid_d;
        int minimum = valid_s < valid_d ? valid_s : valid_d;
        result = (1u << (upper - maximum)) - 1;
        result <<= maximum - minimum;
        for (int i = minimum; i >= 0; i--) {
            result <<= 1;
            result |= pcmp_value(s, control, i) ==
                      pcmp_value(d, control, i);
        }
        break;
    }
    case 3:
        if (valid_d == -1) {
            result = (2u << upper) - 1;
            break;
        }
        for (int j = valid_s == upper ? valid_s : valid_s - valid_d;
             j >= 0; j--) {
            result <<= 1;
            int value = 1;
            int minimum = valid_s - j < valid_d ? valid_s - j : valid_d;
            for (int i = minimum; i >= 0; i--) {
                value &= pcmp_value(s, control, i + j) ==
                         pcmp_value(d, control, i);
            }
            result |= value;
        }
        break;
    }

    switch ((control >> 4) & 3) {
    case 1: result ^= (2u << upper) - 1; break;
    case 3: result ^= (1u << (valid_s + 1)) - 1; break;
    default: break;
    }
    if (result) *eflags |= X86_CC_C;
    else *eflags &= ~X86_CC_C;
    if (result & 1) *eflags |= X86_CC_O;
    else *eflags &= ~X86_CC_O;
    *eflags &= ~(uint64_t)(X86_CC_A | X86_CC_P);
    return result;
}

static void lat_helper_pcmpistri_xmm(unsigned char *env, LatXmm128 *d,
                                     LatXmm128 *s, uint32_t control)
{
    unsigned result = pcmp_result(env, d, s, (uint8_t)control);
    *(uint64_t *)(env + LAT_ENV_RCX_OFFSET) = result ?
        ((control & (1 << 6)) ? 31u - (unsigned)__builtin_clz(result) :
                               (unsigned)__builtin_ctz(result)) :
        16u >> (control & 1);
}

static void lat_helper_pcmpistrm_xmm(unsigned char *env, LatXmm128 *d,
                                     LatXmm128 *s, uint32_t control)
{
    unsigned result = pcmp_result(env, d, s, (uint8_t)control);
    LatXmm128 *xmm0 = (void *)(env + LAT_ENV_XMM0_OFFSET);
    if ((control >> 6) & 1) {
        if (control & 1) {
            for (int i = 0; i < 8; i++, result >>= 1) {
                xmm0->w[i] = (result & 1) ? UINT16_MAX : 0;
            }
        } else {
            for (int i = 0; i < 16; i++, result >>= 1) {
                xmm0->b[i] = (result & 1) ? UINT8_MAX : 0;
            }
        }
    } else {
        xmm0->q[0] = result;
        xmm0->q[1] = 0;
    }
}

static void lat_helper_cpuid(unsigned char *env)
{
    uint64_t *rax = (void *)(env + 344);
    uint64_t *rcx = (void *)(env + 352);
    uint64_t *rdx = (void *)(env + 360);
    uint64_t *rbx = (void *)(env + 368);
    uint32_t leaf = (uint32_t)*rax;
    uint32_t subleaf = (uint32_t)*rcx;
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

    switch (leaf) {
    case 0:
        eax = 7;
        ebx = 0x756e6547; /* GenuineIntel */
        edx = 0x49656e69;
        ecx = 0x6c65746e;
        break;
    case 1:
        eax = 0x00000663;
        edx = (1u << 0) | (1u << 4) | (1u << 5) | (1u << 8) |
              (1u << 15) | (1u << 23) | (1u << 24) | (1u << 25) |
              (1u << 26);
        break;
    case 7:
        if (subleaf == 0) eax = 0;
        break;
    case 0x80000000u:
        eax = 0x80000001u;
        break;
    case 0x80000001u:
        edx = 1u << 29;
        break;
    default:
        break;
    }
    *rax = eax;
    *rbx = ebx;
    *rcx = ecx;
    *rdx = edx;
}

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
    if (syscall_number == 158) {
        uint64_t value = *(uint64_t *)(env + 392);
        switch ((uint32_t)first_argument) {
        case 0x1001:
            *(uint64_t *)(env + LAT_ENV_GS_BASE_OFFSET) = value;
            *(uint64_t *)(env + 344) = 0;
            return;
        case 0x1002:
            *(uint64_t *)(env + LAT_ENV_FS_BASE_OFFSET) = value;
            *(uint64_t *)(env + 344) = 0;
            return;
        case 0x1003:
            *(uint64_t *)(uintptr_t)value =
                *(uint64_t *)(env + LAT_ENV_FS_BASE_OFFSET);
            *(uint64_t *)(env + 344) = 0;
            return;
        case 0x1004:
            *(uint64_t *)(uintptr_t)value =
                *(uint64_t *)(env + LAT_ENV_GS_BASE_OFFSET);
            *(uint64_t *)(env + 344) = 0;
            return;
        default:
            errno = EINVAL;
            *(uint64_t *)(env + 344) = x86_result(-1);
            return;
        }
    }
    if (syscall_number == 218) {
        guest_clear_tid = first_argument;
        *(uint64_t *)(env + 344) = (uint64_t)getpid();
        return;
    }
    if (syscall_number == 273) {
        *(uint64_t *)(env + 344) = 0;
        return;
    }
    if (syscall_number == 334) {
        (void)guest_clear_tid;
        errno = ENOSYS;
        *(uint64_t *)(env + 344) = x86_result(-1);
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
    dprintf(STDERR_FILENO, "latc: unsupported x86 syscall %llu\n",
            (unsigned long long)syscall_number);
    _exit(127);
}
#endif

#define DEFINE_UNSUPPORTED_RUNTIME_ENTRY(name)                         \
    __attribute__((noreturn)) static void unsupported_##name(void)    \
    {                                                                 \
        dprintf(STDERR_FILENO, "latc: unsupported runtime symbol %s\n", \
                #name);                                               \
        abort();                                                       \
    }

DEFINE_UNSUPPORTED_RUNTIME_ENTRY(EPILOGUE_RET_ID_1)
DEFINE_UNSUPPORTED_RUNTIME_ENTRY(EPILOGUE_RET_ID_0)
DEFINE_UNSUPPORTED_RUNTIME_ENTRY(JIRL_EPILOGUE_RET_ID_1)
DEFINE_UNSUPPORTED_RUNTIME_ENTRY(JIRL_EPILOGUE_RET_ID_0)
DEFINE_UNSUPPORTED_RUNTIME_ENTRY(EPILOGUE_RET_0)
DEFINE_UNSUPPORTED_RUNTIME_ENTRY(UPDATE_MXCSR_STATUS)
DEFINE_UNSUPPORTED_RUNTIME_ENTRY(FXSAVE)
DEFINE_UNSUPPORTED_RUNTIME_ENTRY(FXRSTOR)
DEFINE_UNSUPPORTED_RUNTIME_ENTRY(FPREGS_X80_TO_64)
DEFINE_UNSUPPORTED_RUNTIME_ENTRY(FPREGS_64_TO_X80)
DEFINE_UNSUPPORTED_RUNTIME_ENTRY(UPDATE_FP_STATUS)
DEFINE_UNSUPPORTED_RUNTIME_ENTRY(CPUID)
DEFINE_UNSUPPORTED_RUNTIME_ENTRY(RAISE_ILLOP)
DEFINE_UNSUPPORTED_RUNTIME_ENTRY(RAISE_GPF)
DEFINE_UNSUPPORTED_RUNTIME_ENTRY(RAISE_SYSCALL)
DEFINE_UNSUPPORTED_RUNTIME_ENTRY(PCMPISTRI_XMM)
DEFINE_UNSUPPORTED_RUNTIME_ENTRY(PCMPISTRM_XMM)

#define RETURN_UNSUPPORTED_RUNTIME_ENTRY(name)             \
    case LAT_NATIVE_SYMBOL_##name:                         \
        return (uintptr_t)unsupported_##name

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
    if (symbol == LAT_NATIVE_SYMBOL_PCMPISTRI_XMM &&
        (configured_flags & LAT_NATIVE_IMAGE_X86_EXIT_SMOKE)) {
        return (uintptr_t)lat_helper_pcmpistri_xmm;
    }
    if (symbol == LAT_NATIVE_SYMBOL_PCMPISTRM_XMM &&
        (configured_flags & LAT_NATIVE_IMAGE_X86_EXIT_SMOKE)) {
        return (uintptr_t)lat_helper_pcmpistrm_xmm;
    }
    if (symbol == LAT_NATIVE_SYMBOL_CPUID &&
        (configured_flags & LAT_NATIVE_IMAGE_X86_EXIT_SMOKE)) {
        return (uintptr_t)lat_helper_cpuid;
    }
#endif
    switch (symbol) {
    RETURN_UNSUPPORTED_RUNTIME_ENTRY(EPILOGUE_RET_ID_1);
    RETURN_UNSUPPORTED_RUNTIME_ENTRY(EPILOGUE_RET_ID_0);
    RETURN_UNSUPPORTED_RUNTIME_ENTRY(JIRL_EPILOGUE_RET_ID_1);
    RETURN_UNSUPPORTED_RUNTIME_ENTRY(JIRL_EPILOGUE_RET_ID_0);
    RETURN_UNSUPPORTED_RUNTIME_ENTRY(EPILOGUE_RET_0);
    RETURN_UNSUPPORTED_RUNTIME_ENTRY(UPDATE_MXCSR_STATUS);
    RETURN_UNSUPPORTED_RUNTIME_ENTRY(FXSAVE);
    RETURN_UNSUPPORTED_RUNTIME_ENTRY(FXRSTOR);
    RETURN_UNSUPPORTED_RUNTIME_ENTRY(FPREGS_X80_TO_64);
    RETURN_UNSUPPORTED_RUNTIME_ENTRY(FPREGS_64_TO_X80);
    RETURN_UNSUPPORTED_RUNTIME_ENTRY(UPDATE_FP_STATUS);
    RETURN_UNSUPPORTED_RUNTIME_ENTRY(CPUID);
    RETURN_UNSUPPORTED_RUNTIME_ENTRY(RAISE_ILLOP);
    RETURN_UNSUPPORTED_RUNTIME_ENTRY(RAISE_GPF);
    RETURN_UNSUPPORTED_RUNTIME_ENTRY(RAISE_SYSCALL);
    RETURN_UNSUPPORTED_RUNTIME_ENTRY(PCMPISTRI_XMM);
    RETURN_UNSUPPORTED_RUNTIME_ENTRY(PCMPISTRM_XMM);
    default:
        break;
    }
    return 0;
}

void lat_runtime_symbols_configure(uint32_t image_flags)
{
    configured_flags = image_flags;
}
