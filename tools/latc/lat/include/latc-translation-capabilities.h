/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LATC_TRANSLATION_CAPABILITIES_H
#define LATC_TRANSLATION_CAPABILITIES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Neither the AVX nor the non-AVX translator implements AVX-512 today. */
#define LATC_TRANSLATOR_AVX512_SUPPORTED 0

/* Call only after successful instruction decoding, not on arbitrary bytes. */
static inline bool latc_decoded_uses_evex(const uint8_t *bytes, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        switch (bytes[i]) {
        case 0xf0: case 0xf2: case 0xf3: case 0x2e: case 0x36:
        case 0x3e: case 0x26: case 0x64: case 0x65: case 0x66: case 0x67:
            continue;
        default:
            return bytes[i] == 0x62;
        }
    }
    return false;
}

#endif
