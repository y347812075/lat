#!/usr/bin/env python3
"""Check masked PIC discovery without function ownership or supplied keys."""

from pathlib import Path
import struct
import subprocess
import sys

from tb_key_set import read_key_set

latc, guest, output = map(Path, sys.argv[1:])
data = guest.read_bytes()
phoff = struct.unpack_from('<Q', data, 32)[0]
phsize, phnum = struct.unpack_from('<HH', data, 54)
loads = [struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize)
         for i in range(phnum)]
base = min(p[3] - p[2] for p in loads if p[0] == 1)
shoff = struct.unpack_from('<Q', data, 40)[0]
shsize, shnum = struct.unpack_from('<HH', data, 58)
sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shsize)
            for i in range(shnum)]
cases = {}
for section in sections:
    if section[1] != 2:
        continue
    strings = sections[section[6]]
    names = data[strings[4]:strings[4] + strings[5]]
    for off in range(section[4], section[4] + section[5], section[9]):
        name, info, _, _, value, _ = struct.unpack_from('<IBBHQQ', data, off)
        name = names[name:names.index(b'\0', name)].decode()
        if name.startswith('masked_case'):
            assert info & 15 == 0, (name, info)
            cases[name] = (value - base, 3)
assert len(cases) == 3, cases
subprocess.run([str(latc), 'emit-static-tbset', str(guest), '-o', str(output)],
               check=True)
_, _, records = read_key_set(output)
missing = set(cases.values()) - set(records)
assert not missing, missing
print('test-masked-pic-static: PASS')
