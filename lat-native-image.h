#ifndef LATC_LAT_NATIVE_IMAGE_H
#define LATC_LAT_NATIVE_IMAGE_H

#include <stdint.h>

#define LAT_NATIVE_IMAGE_MAGIC "LATNAT2"
#define LAT_NATIVE_IMAGE_VERSION 4u
#define LAT_NATIVE_BUILD_ID_SIZE 65u

enum LatNativeImageFlags {
    LAT_NATIVE_IMAGE_PIE = 1u << 0,
    LAT_NATIVE_IMAGE_NEEDS_FALLBACK = 1u << 1,
    LAT_NATIVE_IMAGE_LBT = 1u << 2,
    LAT_NATIVE_IMAGE_LSX = 1u << 3,
    LAT_NATIVE_IMAGE_NO_PRECISE_SIGNAL_MAP = 1u << 4,
    LAT_NATIVE_IMAGE_CROSS_MODULE_TARGETS = 1u << 5,
    LAT_NATIVE_IMAGE_X86_STATIC_EXEC = 1u << 28,
    LAT_NATIVE_IMAGE_X86_EXIT_SMOKE = LAT_NATIVE_IMAGE_X86_STATIC_EXEC,
    LAT_NATIVE_IMAGE_C_ABI_DISPATCH_SMOKE = 1u << 29,
    LAT_NATIVE_IMAGE_C_ABI_STATE_SMOKE = 1u << 30,
    LAT_NATIVE_IMAGE_C_ABI_SMOKE = 1u << 31,
};

enum LatNativePcMapFlagV2 {
    LAT_NATIVE_PC_MAP_DYNAMIC_STATE = 1u << 0,
};

enum LatNativeRelocationKind {
    LAT_NATIVE_RELOC_RUNTIME_SYMBOL = 1,
    LAT_NATIVE_RELOC_TB_TARGET = 2,
    LAT_NATIVE_RELOC_GUEST_ADDRESS = 3,
    LAT_NATIVE_RELOC_JRRA_TARGET = 4,
};

enum LatNativeRuntimeSymbolV1 {
    LAT_NATIVE_SYMBOL_INVALID = 0,
    LAT_NATIVE_SYMBOL_EPILOGUE_RET_ID_1,
    LAT_NATIVE_SYMBOL_EPILOGUE_RET_ID_0,
    LAT_NATIVE_SYMBOL_JIRL_EPILOGUE_RET_ID_1,
    LAT_NATIVE_SYMBOL_JIRL_EPILOGUE_RET_ID_0,
    LAT_NATIVE_SYMBOL_EPILOGUE_RET_0,
    LAT_NATIVE_SYMBOL_UPDATE_MXCSR_STATUS,
    LAT_NATIVE_SYMBOL_FXSAVE,
    LAT_NATIVE_SYMBOL_FXRSTOR,
    LAT_NATIVE_SYMBOL_FPREGS_X80_TO_64,
    LAT_NATIVE_SYMBOL_FPREGS_64_TO_X80,
    LAT_NATIVE_SYMBOL_UPDATE_FP_STATUS,
    LAT_NATIVE_SYMBOL_CPUID,
    LAT_NATIVE_SYMBOL_RAISE_ILLOP,
    LAT_NATIVE_SYMBOL_RAISE_GPF,
    LAT_NATIVE_SYMBOL_RAISE_SYSCALL,
    LAT_NATIVE_SYMBOL_PFTABLE,
    LAT_NATIVE_SYMBOL_PCMPISTRI_XMM,
    LAT_NATIVE_SYMBOL_PCMPISTRM_XMM,
    LAT_NATIVE_SYMBOL_EFLAGTF,
    LAT_NATIVE_SYMBOL_LOG2,
    LAT_NATIVE_SYMBOL_POW,
    LAT_NATIVE_SYMBOL_SIN,
    LAT_NATIVE_SYMBOL_COS,
    LAT_NATIVE_SYMBOL_ATAN2,
    LAT_NATIVE_SYMBOL_LOGB,
    LAT_NATIVE_SYMBOL_SINCOS,
    LAT_NATIVE_SYMBOL_FPATAN,
    LAT_NATIVE_SYMBOL_FPTAN,
    LAT_NATIVE_SYMBOL_FPREM,
    LAT_NATIVE_SYMBOL_FPREM1,
    LAT_NATIVE_SYMBOL_FRNDINT,
    LAT_NATIVE_SYMBOL_F2XM1,
    LAT_NATIVE_SYMBOL_FXTRACT,
    LAT_NATIVE_SYMBOL_FYL2X,
    LAT_NATIVE_SYMBOL_FYL2XP1,
    LAT_NATIVE_SYMBOL_FSINCOS,
    LAT_NATIVE_SYMBOL_FSIN,
    LAT_NATIVE_SYMBOL_FCOS,
    LAT_NATIVE_SYMBOL_FBLD_ST0,
    LAT_NATIVE_SYMBOL_FBST_ST0,
    LAT_NATIVE_SYMBOL_AESIMC_XMM,
    LAT_NATIVE_SYMBOL_AESKEYGENASSIST_XMM,
    LAT_NATIVE_SYMBOL_AESDEC_XMM,
    LAT_NATIVE_SYMBOL_AESDECLAST_XMM,
    LAT_NATIVE_SYMBOL_AESENC_XMM,
    LAT_NATIVE_SYMBOL_AESENCLAST_XMM,
    LAT_NATIVE_SYMBOL_SHA1NEXTE,
    LAT_NATIVE_SYMBOL_SHA1MSG1,
    LAT_NATIVE_SYMBOL_SHA1MSG2,
    LAT_NATIVE_SYMBOL_SHA256MSG1,
    LAT_NATIVE_SYMBOL_SHA256MSG2,
    LAT_NATIVE_SYMBOL_SHA1RNDS4_F0,
    LAT_NATIVE_SYMBOL_SHA1RNDS4_F1,
    LAT_NATIVE_SYMBOL_SHA1RNDS4_F2,
    LAT_NATIVE_SYMBOL_SHA1RNDS4_F3,
    LAT_NATIVE_SYMBOL_SHA256RNDS2_XMM0,
    LAT_NATIVE_SYMBOL_RAISE_INT,
    LAT_NATIVE_SYMBOL_RAISE_TRAPOP,
    LAT_NATIVE_SYMBOL_RAISE_INTO,
    LAT_NATIVE_SYMBOL_RAISE_BOUND,
    LAT_NATIVE_SYMBOL_XGETBV,
    LAT_NATIVE_SYMBOL_KZT_GET_ALTERNATE,
    LAT_NATIVE_SYMBOL_COUNT,
};

typedef struct LatNativeImageHeaderV2 {
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
    uint64_t pc_map_offset;
    uint64_t pc_map_count;
    uint8_t guest_sha256[32];
    char lat_build_id[LAT_NATIVE_BUILD_ID_SIZE];
    uint8_t reserved_tail[7];
} LatNativeImageHeaderV2;

typedef struct LatNativeTbV1 {
    uint64_t guest_pc;
    uint64_t code_offset;
    uint32_t code_size;
    uint32_t flags;
    uint32_t optimization_flags;
    /* TB-relative instruction offset plus one; zero means unavailable. */
    uint16_t eflags_offset[2];
    uint32_t eflags_instruction;
    uint16_t eflags_stub_offset[2];
} LatNativeTbV1;

enum LatNativeTbOptimizationFlags {
    LAT_NATIVE_TB_ENTRY_FLAGS_DEAD = 1u << 0,
};

typedef struct LatNativeRelocationV1 {
    uint64_t code_offset;
    int64_t addend;
    uint32_t kind;
    uint32_t target;
    uint32_t slots;
    uint32_t reserved;
} LatNativeRelocationV1;

typedef struct LatNativePcMapV2 {
    uint64_t guest_pc;
    uint64_t host_offset_begin;
    uint64_t host_offset_end;
    uint32_t state_record_offset;
    uint32_t flags;
} LatNativePcMapV2;

#endif
