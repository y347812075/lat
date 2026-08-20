#include "runtime-symbols.h"

#include "lat-native-image.h"

#include <stdlib.h>
#include <unistd.h>

static const unsigned char placeholder_pftable[256];
static uint32_t configured_flags;

#if defined(__loongarch__)
__attribute__((noreturn))
static void x86_exit_smoke_syscall(void)
{
    register unsigned char *env __asm__("$s8");
    uint64_t syscall_number = *(uint64_t *)(env + 344);
    uint64_t first_argument = *(uint64_t *)(env + 400);
    _exit(syscall_number == 60 ? (int)first_argument : 127);
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
