#ifndef LATC_LAT_NATIVE_IMAGE_H
#define LATC_LAT_NATIVE_IMAGE_H

#include <stdint.h>

#define LAT_NATIVE_IMAGE_MAGIC "LATNAT1"
#define LAT_NATIVE_IMAGE_VERSION 1u
#define LAT_NATIVE_BUILD_ID_SIZE 65u

enum LatNativeImageFlags {
    LAT_NATIVE_IMAGE_PIE = 1u << 0,
    LAT_NATIVE_IMAGE_NEEDS_FALLBACK = 1u << 1,
    LAT_NATIVE_IMAGE_LBT = 1u << 2,
    LAT_NATIVE_IMAGE_LSX = 1u << 3,
};

enum LatNativeRelocationKind {
    LAT_NATIVE_RELOC_RUNTIME_SYMBOL = 1,
    LAT_NATIVE_RELOC_TB_TARGET = 2,
    LAT_NATIVE_RELOC_GUEST_ADDRESS = 3,
};

typedef struct LatNativeImageHeaderV1 {
    uint8_t magic[8];
    uint32_t version;
    uint32_t header_size;
    uint32_t flags;
    uint32_t reserved;
    uint64_t guest_entry;
    uint64_t preferred_guest_base;
    uint64_t guest_image_offset;
    uint64_t guest_image_size;
    uint64_t code_offset;
    uint64_t code_size;
    uint64_t tb_table_offset;
    uint64_t tb_count;
    uint64_t relocation_offset;
    uint64_t relocation_count;
    uint8_t guest_sha256[32];
    char lat_build_id[LAT_NATIVE_BUILD_ID_SIZE];
    uint8_t reserved_tail[7];
} LatNativeImageHeaderV1;

typedef struct LatNativeTbV1 {
    uint64_t guest_pc;
    uint64_t code_offset;
    uint32_t code_size;
    uint32_t flags;
} LatNativeTbV1;

typedef struct LatNativeRelocationV1 {
    uint64_t code_offset;
    int64_t addend;
    uint32_t kind;
    uint32_t target;
} LatNativeRelocationV1;

#endif
