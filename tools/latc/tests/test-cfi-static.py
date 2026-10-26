#!/usr/bin/env python3
"""Exercise product discovery and reject a broken CFI proof without input keys."""
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from tb_key_set import read_key_set

latc, guest = (Path(arg).resolve() for arg in sys.argv[1:3])
data = guest.read_bytes()
phoff = struct.unpack_from('<Q', data, 32)[0]
phsize, phnum = struct.unpack_from('<HH', data, 54)
loads = [struct.unpack_from('<IIQQQQQQ', data, phoff+i*phsize) for i in range(phnum)]
base = min(p[3]-p[2] for p in loads if p[0] == 1)
shoff = struct.unpack_from('<Q', data, 40)[0]
shsize, shnum = struct.unpack_from('<HH', data, 58)
sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff+i*shsize) for i in range(shnum)]
symbols = {}
for section in sections:
    if section[1] != 2:
        continue
    strings = sections[section[6]]
    names = data[strings[4]:strings[4]+strings[5]]
    for off in range(section[4], section[4]+section[5], section[9]):
        name, info, _, index, value, size = struct.unpack_from('<IBBHQQ', data, off)
        name = names[name:names.index(b'\0', name)].decode()
        symbols[name] = (info & 15, index, value, size)
cases = [symbols['cfi_case'+str(i)] for i in range(2)]
sparse = [symbols['cfi_sparse_case'+str(i)] for i in range(2)]
register = [symbols['cfi_register_case'+str(i)] for i in range(2)]
narrow = [symbols['cfi_narrow_case'+str(i)] for i in range(2)]
byte_cases = [symbols['cfi_byte_case'+str(i)] for i in range(2)]
assert all(case[0] == 0 for case in cases), cases
assert all(case[0] == 0 for case in sparse), sparse
assert all(case[0] == 0 for case in register), register
assert all(case[0] == 0 for case in narrow), narrow
assert all(case[0] == 0 for case in byte_cases), byte_cases
expected = {(case[2]-base, 3) for case in cases}
sparse_expected = {(case[2]-base, 3) for case in sparse}
register_expected = {(case[2]-base, 3) for case in register}
narrow_expected = {(case[2]-base, 3) for case in narrow}
byte_expected = {(case[2]-base, 3) for case in byte_cases}
byte_guard = symbols['cfi_byte_guard']
byte_section = sections[byte_guard[1]]
byte_offset = byte_section[4]+byte_guard[2]-byte_section[3]
assert data[byte_offset+17:byte_offset+24] == bytes.fromhex('4881fae1010000')
byte_filter = symbols['cfi_byte_filter']
byte_filter_offset = byte_section[4]+byte_filter[2]-byte_section[3]
assert data[byte_filter_offset+7:byte_filter_offset+11] == bytes.fromhex('f6041180')
predicate = symbols['cfi_byte_predicate']
guard = symbols['cfi_guard']
section = sections[guard[1]]
offset = section[4]+guard[2]-section[3]
assert data[offset+13:offset+17] == bytes.fromhex('48c1ca06')
sparse_guard = symbols['cfi_sparse_guard']
section = sections[sparse_guard[1]]
sparse_offset = section[4]+sparse_guard[2]-section[3]
assert data[sparse_offset+13:sparse_offset+17] == bytes.fromhex('48c1ca06')
register_guard = symbols['cfi_register_guard']
section = sections[register_guard[1]]
register_offset = section[4]+register_guard[2]-section[3]
assert data[register_offset+13:register_offset+17] == bytes.fromhex('48c1ca08')
register_load = symbols['cfi_register_load']
section = sections[register_load[1]]
load_offset = section[4]+register_load[2]-section[3]
assert data[load_offset:load_offset+4] == bytes.fromhex('488b4010')
narrow_guard = symbols['cfi_narrow_guard']
section = sections[narrow_guard[1]]
narrow_offset = section[4]+narrow_guard[2]-section[3]
assert data[narrow_offset+13:narrow_offset+17] == bytes.fromhex('48c1ca06')
narrow_mask = symbols['cfi_narrow_mask']
section = sections[narrow_mask[1]]
mask_offset = section[4]+narrow_mask[2]-section[3]
assert data[mask_offset:mask_offset+2] == bytes.fromhex('41bf')
assert data[mask_offset+6:mask_offset+10] == bytes.fromhex('410fa3d7')
narrow_load = symbols['cfi_narrow_load']
section = sections[narrow_load[1]]
narrow_load_offset = section[4]+narrow_load[2]-section[3]
assert data[narrow_load_offset:narrow_load_offset+4] == bytes.fromhex('0fb63424')
with tempfile.TemporaryDirectory(prefix='latc-cfi-static-') as temp:
    root = Path(temp)
    for mode in ('positive', 'broken-guard', 'broken-sparse-guard',
                 'broken-register-guard', 'broken-register-value',
                 'broken-narrow-guard', 'broken-narrow-width', 'broken-narrow-value',
                 'broken-byte-guard', 'broken-byte-bound', 'broken-byte-index',
                 'broken-byte-mask', 'broken-byte-writable', 'broken-byte-relocation'):
        source = guest
        if mode != 'positive':
            source = root/'broken-guest'
            broken = bytearray(data)
            if mode == 'broken-byte-bound':
                struct.pack_into('<I', broken, byte_offset+20, 512)
            elif mode == 'broken-byte-index':
                broken[byte_filter_offset+9] = 0x51  # Wrong scaled index.
            elif mode == 'broken-byte-mask':
                broken[byte_filter_offset+10] = 0
            elif mode == 'broken-byte-writable':
                for i, ph in enumerate(loads):
                    if ph[0] == 1 and ph[3] <= predicate[2] < ph[3]+ph[6]:
                        struct.pack_into('<I', broken, phoff+i*phsize+4, ph[1] | 2)
            elif mode == 'broken-byte-relocation':
                rela = next(s for s in sections if s[1] == 4 and s[2] & 2)
                slot = symbols['cfi_byte_table'][2] + 8
                at = next(at for at in range(rela[4], rela[4]+rela[5], rela[9])
                          if struct.unpack_from('<Q', data, at)[0] == slot)
                struct.pack_into('<Q', broken, at, predicate[2])
            elif mode == 'broken-register-value':
                broken[load_offset+8] = 0xc0  # XOR EAX,EAX kills loaded target.
            elif mode == 'broken-narrow-width':
                broken[mask_offset+6] = 0x49  # BT64 does not match MOV32 width.
            elif mode == 'broken-narrow-value':
                broken[narrow_load_offset+2] = 0x04  # MOVZX EAX destroys pointer.
            else:
                at = {'broken-guard': offset, 'broken-sparse-guard': sparse_offset,
                      'broken-register-guard': register_offset,
                      'broken-narrow-guard': narrow_offset,
                      'broken-byte-guard': byte_offset}[mode]
                broken[at+15] = 0xe2  # SHL is not the ROR inverse constraint.
            source.write_bytes(broken)
        output = root/(mode+'.tbset')
        subprocess.run([str(latc), 'emit-static-tbset', str(source), '-o', str(output)],
                       check=True)
        _, _, records = read_key_set(output)
        actual = set(records)
        for targets, broken_modes in ((expected, ('broken-guard',)),
                                      (sparse_expected, ('broken-sparse-guard',)),
                                      (register_expected, ('broken-register-guard',
                                                           'broken-register-value')),
                                      (narrow_expected, ('broken-narrow-guard',
                                                         'broken-narrow-width',
                                                         'broken-narrow-value')),
                                      (byte_expected, ('broken-byte-guard',
                                                       'broken-byte-bound',
                                                       'broken-byte-index',
                                                       'broken-byte-mask',
                                                       'broken-byte-writable',
                                                       'broken-byte-relocation'))):
            if mode in broken_modes:
                assert not targets & actual, targets & actual
            else:
                assert targets <= actual, targets-actual
        print(mode, 'keys=', len(actual), 'source_sha256=', hashlib.sha256(source.read_bytes()).hexdigest())
print('test-cfi-static: PASS')
