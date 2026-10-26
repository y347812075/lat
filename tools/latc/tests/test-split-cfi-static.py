#!/usr/bin/env python3
"""Product discovery of split rotation without requested keys or function types."""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from tb_key_set import read_key_set

latc, guest = map(lambda value: Path(value).resolve(), sys.argv[1:3])
data = guest.read_bytes()
phoff, shoff = struct.unpack_from('<QQ', data, 32)
phsize, phnum, shsize, shnum = struct.unpack_from('<HHHH', data, 54)
phdrs = [struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize)
         for i in range(phnum)]
base = min(p[3] - p[2] for p in phdrs if p[0] == 1)
sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shsize)
            for i in range(shnum)]
symbols = {}
for section in sections:
    if section[1] != 2:
        continue
    strings = sections[section[6]]
    names = data[strings[4]:strings[4] + strings[5]]
    for at in range(section[4], section[4] + section[5], section[9]):
        name, info, _, index, value, size = struct.unpack_from('<IBBHQQ', data, at)
        symbols[names[name:names.index(b'\0', name)].decode()] = (info & 15, index, value, size)
cases = [symbols['split_case' + str(i)] for i in range(2)]
assert all(case[0] == 0 for case in cases)
expected = {(case[2] - base, 3) for case in cases}
proof = symbols['split_proof']
section = sections[proof[1]]
offset = section[4] + proof[2] - section[3]
complement = symbols['split_complement']
complement_offset = section[4] + complement[2] - section[3]
preserve = symbols['split_preserve']
preserve_offset = section[4] + preserve[2] - section[3]
restore = symbols['split_preserve_restore']
restore_offset = section[4] + restore[2] - section[3]
writer = symbols['split_write_local']
writer_offset = section[4] + writer[2] - section[3]
setcc = symbols['split_setcc_store']
setcc_offset = section[4] + setcc[2] - section[3]
assert data[offset:offset + 3] == bytes.fromhex('4889c2')
assert data[offset + 19:offset + 22] == bytes.fromhex('48d3ee')
assert data[offset + 25:offset + 28] == bytes.fromhex('48d3e2')
with tempfile.TemporaryDirectory(prefix='latc-split-cfi-') as temp:
    root = Path(temp)
    for mode in ('positive', 'wrong-shift', 'wrong-width', 'different-source',
                 'noncomplement', 'signed-guard', 'data-only-decoy', 'call-clobber',
                 'helper-relocation', 'helper-writable', 'child-saved-overlap',
                 'child-parent-return-overlap', 'child-return-overlap',
                 'setcc-saved-overlap', 'setcc-return-overlap'):
        if len(sys.argv) > 3 and mode not in sys.argv[3:]:
            continue
        source = root / (mode + '.guest')
        changed = bytearray(data)
        if mode == 'wrong-shift':
            changed[offset + 21] = 0xfe  # SAR instead of SHR.
        elif mode == 'wrong-width':
            changed[offset + 19] = 0x40
        elif mode == 'different-source':
            changed[offset + 15] = 0xde  # Copy RBX instead of the delta.
        elif mode == 'noncomplement':
            assert changed[complement_offset:complement_offset + 2] == bytes((0xb1, 64))
            changed[complement_offset + 1] = 63
        elif mode == 'signed-guard':
            assert changed[offset + 35] == 0x77
            changed[offset + 35] = 0x7f
        elif mode == 'data-only-decoy':
            index = proof[1]
            struct.pack_into('<Q', changed, shoff + index * shsize + 8,
                             section[2] & ~4)  # Remove SHF_EXECINSTR.
        elif mode == 'call-clobber':
            assert changed[preserve_offset:preserve_offset + 2] == bytes.fromhex('4157')
            changed[preserve_offset:preserve_offset + 2] = bytes.fromhex('9090')
            assert changed[restore_offset:restore_offset + 2] == bytes.fromhex('415f')
            changed[restore_offset:restore_offset + 2] = bytes.fromhex('9090')
        elif mode == 'helper-relocation':
            rela = next(s for s in sections if s[1] == 4 and s[2] & 2)
            at = next(at for at in range(rela[4], rela[4] + rela[5], rela[9])
                      if struct.unpack_from('<Q', data, at)[0] == symbols['split_spare_reloc'][2])
            struct.pack_into('<Q', changed, at, preserve[2] + 3)
        elif mode == 'helper-writable':
            for i, ph in enumerate(phdrs):
                if ph[0] == 1 and ph[3] <= preserve[2] < ph[3] + ph[6]:
                    struct.pack_into('<I', changed, phoff + i * phsize + 4,
                                     ph[1] | 2)
        elif mode.startswith('child-'):
            assert changed[preserve_offset + 12:preserve_offset + 17] == bytes.fromhex('488d7c2408')
            changed[preserve_offset + 16] = {
                'child-saved-overlap': 32,
                'child-parent-return-overlap': 40,
                'child-return-overlap': 0xf8,
            }[mode]
            if mode == 'child-saved-overlap':
                assert changed[writer_offset + 11:writer_offset + 15] == bytes.fromhex('48895708')
                changed[writer_offset + 11:writer_offset + 15] = bytes.fromhex('90909090')
        elif mode.startswith('setcc-'):
            assert changed[setcc_offset:setcc_offset + 4] == bytes.fromhex('0f904710')
            changed[setcc_offset + 3] = {
                'setcc-saved-overlap': 24,
                'setcc-return-overlap': 32,
            }[mode]
        source.write_bytes(changed)
        output = root / (mode + '.tbset')
        subprocess.run([str(latc), 'emit-static-tbset', str(source), '-o', str(output)],
                       check=True)
        _, _, records = read_key_set(output)
        actual = set(records)
        if mode == 'positive':
            assert expected <= actual, expected - actual
        else:
            assert not expected & actual, expected & actual
        print(mode, 'keys=', len(actual))
print('test-split-cfi-static: PASS')
