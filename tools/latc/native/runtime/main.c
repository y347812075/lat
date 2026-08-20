#include "native-image.h"
#include "lat-fallback.h"
#include "guest-loader.h"
#include "relocate.h"
#include "dispatch.h"
#include "enter-x86.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const unsigned char latc_embedded_image_start[];
extern const unsigned char latc_embedded_image_end[];

#define LATC_X86_EXIT_SMOKE_BUILD_ID \
    "lat-42c042301e107b34063773e118c825dd644d476c-x64-v1"

static const unsigned char latc_x86_exit_smoke_sha256[][32] = {
    {
        0x0b, 0xd9, 0x23, 0xe5, 0xea, 0x65, 0xb3, 0x2a,
        0xb8, 0x92, 0x3e, 0xc5, 0x6b, 0x74, 0x79, 0xbd,
        0x53, 0x5a, 0xe8, 0xba, 0xf3, 0xde, 0x0e, 0xa5,
        0x63, 0x67, 0x90, 0x30, 0xc6, 0x88, 0x91, 0xbd,
    },
    {
        0xb1, 0x00, 0x8e, 0xe8, 0x00, 0xbb, 0x0e, 0x09,
        0xf2, 0x8e, 0x10, 0xb0, 0x3d, 0x32, 0xac, 0xe8,
        0xd1, 0x60, 0xc1, 0x4e, 0xa9, 0xba, 0x37, 0x51,
        0xef, 0x7a, 0x83, 0xdf, 0x40, 0x94, 0x52, 0x80,
    },
};

static int x86_exit_smoke_guest_allowed(const unsigned char digest[32])
{
    for (size_t i = 0; i < sizeof(latc_x86_exit_smoke_sha256) /
                            sizeof(latc_x86_exit_smoke_sha256[0]); i++) {
        if (!memcmp(digest, latc_x86_exit_smoke_sha256[i], 32)) return 1;
    }
    return 0;
}

static int inspect_image(const LatNativeImageHeaderV1 *header)
{
    printf("execution_model=lat-native-pie-shell\n"
           "guest_entry=0x%" PRIx64 "\n"
           "guest_size=%" PRIu64 "\n"
           "code_size=%" PRIu64 "\n"
           "tbs=%" PRIu64 "\n"
           "relocations=%" PRIu64 "\n"
           "flags=0x%x\n"
           "lat_build_id=%s\n",
           header->guest_entry, header->guest_image_size,
           header->code_size, header->tb_count,
           header->relocation_count, header->flags,
           header->lat_build_id);
    return 0;
}

int main(int argc, char **argv)
{
    size_t image_size = (size_t)(latc_embedded_image_end -
                                 latc_embedded_image_start);
    char error[256] = {0};
    if (lat_native_image_validate(latc_embedded_image_start, image_size,
                                  error, sizeof(error)) != 0) {
        fprintf(stderr, "latc: invalid embedded native image: %s\n", error);
        return 125;
    }
    const LatNativeImageHeaderV1 *header =
        (const void *)latc_embedded_image_start;
    if (argc == 2 && strcmp(argv[1], "--latc-inspect") == 0) {
        return inspect_image(header);
    }
    if (argc == 2 && strcmp(argv[1], "--latc-map") == 0) {
        LatGuestMapping mapping = {0};
        if (lat_guest_map(header, latc_embedded_image_start, image_size,
                          &mapping, error, sizeof(error))) {
            fprintf(stderr, "latc: cannot map embedded guest: %s\n", error);
            return 124;
        }
        printf("guest_base=0x%" PRIx64 "\n"
               "guest_end=0x%" PRIx64 "\n"
               "guest_entry=0x%" PRIx64 "\n",
               mapping.base, mapping.end, mapping.entry);
        lat_guest_unmap(&mapping);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--latc-relocate") == 0) {
        LatNativeCode code = {0};
        if (lat_native_code_load(header, latc_embedded_image_start, image_size,
                                 &code, error, sizeof(error))) {
            fprintf(stderr, "latc: cannot relocate native code: %s\n", error);
            return 123;
        }
        printf("native_code=%p\nnative_code_size=%zu\nrelocations=%" PRIu64
               "\n", code.address, code.size, header->relocation_count);
        lat_native_code_unload(&code);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--latc-run-smoke") == 0) {
        if (!(header->flags & LAT_NATIVE_IMAGE_C_ABI_SMOKE)) {
            fprintf(stderr, "latc: image is not a C ABI smoke test\n");
            return 122;
        }
        const LatNativeTbV1 *tb = lat_native_tb_find(
            header, latc_embedded_image_start, image_size,
            header->guest_entry, 0);
        if (!tb) {
            fprintf(stderr, "latc: smoke entry TB is missing\n");
            return 121;
        }
        LatNativeCode code = {0};
        if (lat_native_code_load(header, latc_embedded_image_start, image_size,
                                 &code, error, sizeof(error))) {
            fprintf(stderr, "latc: cannot load smoke code: %s\n", error);
            return 120;
        }
        int (*entry)(void) = (void *)((unsigned char *)code.address +
                                      tb->code_offset);
        int result = entry();
        lat_native_code_unload(&code);
        printf("smoke_result=%d\n", result);
        return result == 42 ? 0 : 119;
    }
    if (argc == 2 && strcmp(argv[1], "--latc-run-state-smoke") == 0) {
        if (!(header->flags & LAT_NATIVE_IMAGE_C_ABI_STATE_SMOKE)) {
            fprintf(stderr, "latc: image is not a state ABI smoke test\n");
            return 118;
        }
        const LatNativeTbV1 *tb = lat_native_tb_find(
            header, latc_embedded_image_start, image_size,
            header->guest_entry, 0);
        LatNativeCode code = {0};
        if (!tb || lat_native_code_load(header, latc_embedded_image_start,
                                        image_size, &code, error,
                                        sizeof(error))) {
            fprintf(stderr, "latc: cannot load state smoke code: %s\n",
                    tb ? error : "entry TB is missing");
            return 117;
        }
        LatX86StateV1 state = {0};
        state.gpr[0] = 35;
        int (*entry)(LatX86StateV1 *) =
            (void *)((unsigned char *)code.address + tb->code_offset);
        int result = entry(&state);
        lat_native_code_unload(&code);
        printf("state_result=%d\ngpr0=%" PRIu64 "\nrip=0x%" PRIx64 "\n",
               result, state.gpr[0], state.rip);
        return result == 42 && state.gpr[0] == 42 && state.rip == 0x1234 ?
            0 : 116;
    }
    if (argc == 2 && strcmp(argv[1], "--latc-run-dispatch-smoke") == 0) {
        if (!(header->flags & LAT_NATIVE_IMAGE_C_ABI_DISPATCH_SMOKE)) {
            fprintf(stderr, "latc: image is not a dispatch smoke test\n");
            return 115;
        }
        LatNativeCode code = {0};
        if (lat_native_code_load(header, latc_embedded_image_start, image_size,
                                 &code, error, sizeof(error))) {
            fprintf(stderr, "latc: cannot load dispatch smoke code: %s\n",
                    error);
            return 114;
        }
        LatX86StateV1 state = {0};
        state.gpr[0] = 5;
        state.rip = header->guest_entry;
        unsigned steps = 0;
        int tb_result = 0;
        while (state.rip && steps < 8) {
            const LatNativeTbV1 *tb = lat_native_tb_find(
                header, latc_embedded_image_start, image_size, state.rip, 0);
            if (!tb) {
                tb_result = -1;
                break;
            }
            int (*entry)(LatX86StateV1 *) =
                (void *)((unsigned char *)code.address + tb->code_offset);
            tb_result = entry(&state);
            steps++;
            if (tb_result) break;
        }
        lat_native_code_unload(&code);
        printf("dispatch_steps=%u\ngpr0=%" PRIu64 "\nrip=0x%" PRIx64
               "\ntb_result=%d\n", steps, state.gpr[0], state.rip,
               tb_result);
        return steps == 2 && state.gpr[0] == 24 && state.rip == 0 &&
               tb_result == 0 ? 0 : 113;
    }
    if (argc == 2 && strcmp(argv[1], "--latc-run-x86-exit-smoke") == 0) {
        if (!(header->flags & LAT_NATIVE_IMAGE_X86_EXIT_SMOKE) ||
            strcmp(header->lat_build_id, LATC_X86_EXIT_SMOKE_BUILD_ID) ||
            !x86_exit_smoke_guest_allowed(header->guest_sha256)) {
            fprintf(stderr, "latc: image is not a compatible x86 exit smoke\n");
            return 112;
        }
        LatGuestMapping mapping = {0};
        LatNativeCode code = {0};
        const LatNativeTbV1 *tb = lat_native_tb_find(
            header, latc_embedded_image_start, image_size,
            header->guest_entry, 0);
        if (!tb || lat_guest_map(header, latc_embedded_image_start, image_size,
                                 &mapping, error, sizeof(error)) ||
            lat_native_code_load(header, latc_embedded_image_start, image_size,
                                 &code, error, sizeof(error))) {
            fprintf(stderr, "latc: cannot prepare x86 exit smoke: %s\n",
                    tb ? error : "entry TB is missing");
            lat_guest_unmap(&mapping);
            lat_native_code_unload(&code);
            return 111;
        }
        void *environment = calloc(1, 4096);
        if (!environment) {
            fprintf(stderr, "latc: cannot allocate x86 exit environment\n");
            lat_guest_unmap(&mapping);
            lat_native_code_unload(&code);
            return 110;
        }
        void *entry = (unsigned char *)code.address + tb->code_offset;
        lat_native_enter_x86_exit_smoke(entry, environment);
    }
    if (argc > 1 && (strcmp(argv[1], "--latc-inspect") == 0 ||
                     strcmp(argv[1], "--latc-map") == 0 ||
                     strcmp(argv[1], "--latc-relocate") == 0 ||
                     strcmp(argv[1], "--latc-run-smoke") == 0 ||
                     strcmp(argv[1], "--latc-run-state-smoke") == 0 ||
                     strcmp(argv[1], "--latc-run-dispatch-smoke") == 0 ||
                     strcmp(argv[1], "--latc-run-x86-exit-smoke") == 0)) {
        fprintf(stderr,
                "usage: %s [--latc-inspect|--latc-map|--latc-relocate|"
                "--latc-run-smoke|--latc-run-state-smoke|"
                "--latc-run-dispatch-smoke|--latc-run-x86-exit-smoke]\n",
                argv[0]);
        return 2;
    }
    fprintf(stderr,
            "latc: native PIE shell is valid but guest execution is not linked yet\n");
    return 126;
}
