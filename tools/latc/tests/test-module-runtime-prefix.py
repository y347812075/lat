#!/usr/bin/env python3
"""Check large-module runtime reachability without allocating huge images."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'aot-v2/compiler/module-pack.c').read_text()
functions = source[source.index('static uint64_t runtime_target('):
                   source.index('static gint compare_tb_code(')]
harness = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include "lat-native-image.h"
typedef struct {
    const LatNativeImageHeaderV2 *header;
    LatNativeTbV1 *tbs;
    LatNativeRelocationV1 *relocations;
    LatNativePcMapV2 *pc_maps;
    uint64_t runtime_trampolines, runtime_prefix, pf_table;
} ModulePack;
'''
checks = r'''
int main(void) {
    LatNativeImageHeaderV2 header = {.tb_count=1, .relocation_count=2, .pc_map_count=1};
    LatNativeTbV1 tb = {.code_offset=64};
    LatNativeRelocationV1 rel[2] = {
        {.code_offset=68, .kind=LAT_NATIVE_RELOC_IMAGE_DATA, .addend=144,
         .data_object_offset=128, .data_object_size=64,
         .data_object_alignment=32, .data_object_flags=LAT_NATIVE_DATA_POINTER_FREE},
        {.code_offset=72, .kind=LAT_NATIVE_RELOC_TB_TARGET, .addend=0x400000},
    };
    LatNativePcMapV2 map = {.host_offset_begin=64, .host_offset_end=80, .guest_pc=42};
    ModulePack pack = {.header=&header, .tbs=&tb, .relocations=rel, .pc_maps=&map,
        .runtime_trampolines=UINT64_C(3200000000), .runtime_prefix=4096,
        .pf_table=UINT64_C(3200000000)+LAT_NATIVE_SYMBOL_COUNT*4};
    for (uint64_t site=4096; site<pack.runtime_trampolines; site+=1048576) {
        uint64_t target=runtime_target(&pack, site, LAT_NATIVE_SYMBOL_RAISE_SYSCALL);
        int64_t distance=(int64_t)target-(int64_t)site;
        assert(distance > -INT64_C(2147480000) && distance < INT64_C(2147480000));
    }
    assert(runtime_target(&pack, 4096, LAT_NATIVE_SYMBOL_PFTABLE)==LAT_NATIVE_SYMBOL_COUNT*8);
    shift_runtime_prefix(&pack);
    assert(tb.code_offset==4160 && rel[0].code_offset==4164 && rel[0].addend==4240);
    assert(rel[0].data_object_offset==4224 && rel[0].data_object_size==64);
    assert(rel[0].data_object_alignment==32 && rel[0].data_object_flags==LAT_NATIVE_DATA_POINTER_FREE);
    assert(rel[1].addend==0x400000 && map.host_offset_begin==4160 && map.host_offset_end==4176);
    assert(map.guest_pc==42);
    pack.runtime_prefix=0;
    assert(runtime_target(&pack, 4096, 5)==pack.runtime_trampolines+20);
    shift_runtime_prefix(&pack);
    assert(tb.code_offset==4160);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='latc-prefix-') as temp:
    path = Path(temp)
    (path / 'test.c').write_text(harness + functions + checks)
    subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
        '-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(root / 'native/include'),
        str(path / 'test.c'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True)
print('test-module-runtime-prefix: PASS')
