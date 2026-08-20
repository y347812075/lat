#include "native-image.h"
#include "guest-loader.h"
#include "relocate.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

extern const unsigned char latc_embedded_image_start[];
extern const unsigned char latc_embedded_image_end[];

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
    if (argc > 1 && (strcmp(argv[1], "--latc-inspect") == 0 ||
                     strcmp(argv[1], "--latc-map") == 0 ||
                     strcmp(argv[1], "--latc-relocate") == 0)) {
        fprintf(stderr,
                "usage: %s [--latc-inspect|--latc-map|--latc-relocate]\n",
                argv[0]);
        return 2;
    }
    fprintf(stderr,
            "latc: native PIE shell is valid but guest execution is not linked yet\n");
    return 126;
}
