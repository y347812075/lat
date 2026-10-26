#include "lat-tb-key-set.h"
#include "lat-aot-v2.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static LatTbKeySet make_set(size_t count, uint64_t first)
{
    LatTbKeySet set = { .count = count, .sequence = first };
    set.keys = count ? calloc(count, sizeof(*set.keys)) : NULL;
    assert(!count || set.keys);
    for (size_t i = 0; i < count; i++) {
        set.keys[i] = (LatTbKey) {
            .guest_rva = first + i,
            .flags = LAT_AOT_TB_CODE64 | LAT_AOT_TB_PARALLEL,
        };
    }
    return set;
}

int main(void)
{
    char error[256] = {0};
    LatTbKeySet ordered = make_set(4, 1);
    LatTbKey *original_keys = ordered.keys;
    assert(!lat_tb_key_set_sort_unique(&ordered, error, sizeof(error)));
    assert(ordered.keys == original_keys && ordered.count == 4);
    ordered.keys[3].reserved = 1;
    assert(lat_tb_key_set_sort_unique(&ordered, error, sizeof(error)) < 0);
    ordered.keys[3].reserved = 0;
    ordered.keys[2] = ordered.keys[1];
    assert(!lat_tb_key_set_sort_unique(&ordered, error, sizeof(error)));
    assert(ordered.count == 3 && ordered.keys[2].guest_rva == 4);
    ordered.keys[0].guest_rva = 9;
    assert(!lat_tb_key_set_sort_unique(&ordered, error, sizeof(error)));
    assert(ordered.count == 3 && ordered.keys[0].guest_rva == 2 &&
           ordered.keys[2].guest_rva == 9);
    lat_tb_key_set_destroy(&ordered);
    unsigned random_state = 1;
    for (unsigned trial = 0; trial < 256; trial++) {
        LatTbKeySet sample = make_set(trial, 0);
        unsigned char seen[64] = {0};
        for (size_t i = 0; i < sample.count; i++) {
            random_state = random_state * 1664525u + 1013904223u;
            sample.keys[i].guest_rva = (random_state >> 16) % 64;
            seen[sample.keys[i].guest_rva] = 1;
        }
        assert(!lat_tb_key_set_sort_unique(&sample, error, sizeof(error)));
        size_t index = 0;
        for (unsigned rva = 0; rva < sizeof(seen); rva++) {
            if (seen[rva]) {
                assert(index < sample.count && sample.keys[index++].guest_rva == rva);
            }
        }
        assert(index == sample.count);
        assert(!lat_tb_key_set_sort_unique(&sample, error, sizeof(error)));
        assert(index == sample.count);
        lat_tb_key_set_destroy(&sample);
    }
    const size_t limit = LAT_AOT_V2_TBSET_RECORD_LIMIT;
    LatTbKeySet left = make_set(limit, 0);
    LatTbKeySet right = make_set(limit, 0);
    LatTbKeySet result = {0};
    right.sequence = 9;
    /* The record limit applies to the unique union, not the input sum. */
    assert(!lat_tb_key_set_union(&left, &right, &result,
                                 error, sizeof(error)));
    assert(result.count == limit && result.sequence == 9);
    assert(!memcmp(left.keys, result.keys, limit * sizeof(*left.keys)));
    lat_tb_key_set_destroy(&result);

    right.count = 1;
    right.keys[0].guest_rva = limit;
    assert(lat_tb_key_set_union(&left, &right, &result,
                                error, sizeof(error)) < 0);
    assert(errno == E2BIG && !result.keys && !result.count);
    assert(left.count == limit && left.keys[limit - 1].guest_rva == limit - 1);

    left.count = limit - 1;
    assert(!lat_tb_key_set_union(&left, &right, &result,
                                 error, sizeof(error)));
    assert(result.count == limit && result.keys[limit - 1].guest_rva == limit);
    lat_tb_key_set_destroy(&result);
    right.count = limit + 1;
    assert(lat_tb_key_set_union(&left, &right, &result,
                                error, sizeof(error)) < 0);
    right.count = 1;
    right.keys[0].reserved = 1;
    assert(lat_tb_key_set_union(&left, &right, &result,
                                error, sizeof(error)) < 0);
    assert(!result.keys && !result.count);
    lat_tb_key_set_destroy(&left);
    lat_tb_key_set_destroy(&right);

    left = make_set(3, 1);
    right = make_set(2, 2);
    left.keys[0].guest_rva = 3;
    left.keys[2].guest_rva = 1;
    assert(!lat_tb_key_set_union(&left, &right, &result,
                                 error, sizeof(error)));
    assert(result.count == 3);
    for (size_t i = 0; i < result.count; i++) {
        assert(result.keys[i].guest_rva == i + 1);
    }
    lat_tb_key_set_destroy(&result);
    right.source_sha256[0] = 1;
    assert(lat_tb_key_set_union(&left, &right, &result,
                                error, sizeof(error)) < 0);
    lat_tb_key_set_destroy(&left);
    lat_tb_key_set_destroy(&right);
    assert(!lat_tb_key_set_union(&left, &right, &result,
                                 error, sizeof(error)));
    assert(!result.count);
    lat_tb_key_set_destroy(&result);
    puts("TB key union capacity tests passed");
    return 0;
}
