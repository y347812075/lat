#!/usr/bin/env python3
"""Keep an executable ELF entry even without a function symbol."""
from pathlib import Path
import struct
import subprocess
import sys
from tb_key_set import read_key_set

latc, source, output = sys.argv[1:]
data = bytearray(Path(source).read_bytes())
entry = struct.unpack_from('<Q', data, 24)[0]
phoff, shoff = struct.unpack_from('<QQ', data, 32)
phentsize, phnum, shentsize, shnum = struct.unpack_from('<HHHH', data, 54)
base = min(struct.unpack_from('<Q', data, phoff + i * phentsize + 16)[0]
           for i in range(phnum)
           if struct.unpack_from('<I', data, phoff + i * phentsize)[0] == 1)
changed = 0
for i in range(shnum):
    sh = shoff + i * shentsize
    if struct.unpack_from('<I', data, sh + 4)[0] not in (2, 11):
        continue
    offset, size = struct.unpack_from('<QQ', data, sh + 24)
    stride = struct.unpack_from('<Q', data, sh + 56)[0]
    for sym in range(offset, offset + size, stride):
        value = struct.unpack_from('<Q', data, sym + 8)[0]
        if data[sym + 4] & 15 == 2 and value == entry:
            data[sym + 4] &= 0xf0
            changed += 1
assert changed, 'fixture needs a function symbol at its ELF entry'
guest = Path(output + '.elf')
guest.write_bytes(data)
subprocess.run([latc, 'emit-static-tbset', str(guest), '-o', output], check=True)
assert (entry - base, 3) in read_key_set(Path(output))[2], 'missing symbol-less ELF entry'

# With no function metadata, the entry's call may reach a helper after its ret.
# Keep the conservative entry extent until direct closure covers that root.
probe = bytearray(data)
for i in range(shnum):
    sh = shoff + i * shentsize
    kind = struct.unpack_from('<I', probe, sh + 4)[0]
    if kind in (2, 11):
        struct.pack_into('<I', probe, sh + 4, 1)
    flags, address, offset, size = struct.unpack_from('<QQQQ', probe, sh + 8)
    if flags & 4 and address <= entry < address + size:
        entry_offset = offset + entry - address
        available = size - (entry - address)
assert available >= 32
helper = entry + 16
probe[entry_offset:entry_offset + 32] = (
    b'\xe8\x0b\0\0\0\xc3' + b'\xcc' * 10 + b'\xc3' + b'\xcc' * 15
)
guest.write_bytes(probe)
subprocess.run([latc, 'emit-static-tbset', str(guest), '-o', output], check=True)
assert (helper - base, 3) in read_key_set(Path(output))[2], 'entry lost post-ret callee'

# An entry in the read-only ELF header must not become executable code.
struct.pack_into('<Q', data, 24, base)
guest.write_bytes(data)
subprocess.run([latc, 'emit-static-tbset', str(guest), '-o', output], check=True)
assert (0, 3) not in read_key_set(Path(output))[2], 'non-executable entry accepted'
print('test-static-entry: PASS')
