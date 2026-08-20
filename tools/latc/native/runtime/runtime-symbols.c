#include "runtime-symbols.h"

#include "lat-native-image.h"

#include <stdlib.h>

static const unsigned char placeholder_pftable[256];

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
    if (symbol > LAT_NATIVE_SYMBOL_INVALID &&
        symbol < LAT_NATIVE_SYMBOL_COUNT) {
        return (uintptr_t)unsupported_runtime_entry;
    }
    return 0;
}
