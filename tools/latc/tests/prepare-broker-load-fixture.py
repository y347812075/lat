#!/usr/bin/env python3
"""Prepare an isolated, synthetic config module for broker LOAD tests."""
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

fixture, guest, config, build_id, cache = sys.argv[1:]
data = bytearray(Path(fixture).read_bytes())
source = hashlib.sha256(Path(guest).read_bytes()).digest()
cfg = Path(config).read_bytes()
assert cfg[:8] == b'LATCFG1\0' and len(cfg) >= 64
config_hash = hashlib.sha256(cfg[:32] + cfg[64:]).digest()
codegen = hashlib.sha256(build_id.encode()).digest()
assert data[:6] == b'\x7fELF\x02\x01'
shoff = struct.unpack_from('<Q', data, 40)[0]
shentsize, shnum = struct.unpack_from('<HH', data, 58)
sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize)
            for i in range(shnum)]
found_note = found_symbol = False
for section in sections:
    kind, offset, size, link, entsize = section[1], section[4], section[5], section[6], section[9]
    if kind == 7:
        cursor = offset
        while cursor < offset + size:
            namesz, descsz, note_type = struct.unpack_from('<III', data, cursor)
            name = cursor + 12
            desc = name + ((namesz + 3) & ~3)
            if note_type == 0x4c415432 and data[name:name + namesz] == b'LAT\0':
                assert descsz == 176 and data[desc:desc + 8] == b'LATAOT2\0'
                data[desc + 32:desc + 64] = source
                data[desc + 64:desc + 96] = codegen
                data[desc + 144:desc + 176] = config_hash
                found_note = True
            cursor = desc + ((descsz + 3) & ~3)
    if kind != 11:
        continue
    strings = sections[link]
    strtab = data[strings[4]:strings[4] + strings[5]]
    for pos in range(offset, offset + size, entsize):
        name, _, _, shndx, value, symsize = struct.unpack_from('<IBBHQQ', data, pos)
        end = strtab.find(b'\0', name)
        if strtab[name:end] != b'lat_aot_module_v2':
            continue
        target = sections[shndx]
        loc = target[4] + value - target[3]
        assert symsize >= 176 and data[loc:loc + 8] == b'LATAOT2\0'
        data[loc + 32:loc + 64] = source
        data[loc + 64:loc + 96] = codegen
        data[loc + symsize - 32:loc + symsize] = config_hash
        found_symbol = True
assert found_note and found_symbol
hex_source = source.hex()
module_name = hex_source + '.so'
module = Path(cache) / module_name
module.write_bytes(data)
os.chmod(module, 0o444)
manifest = {'version': 2, 'module': module_name, 'native': hex_source + '.native',
            'tbset': '', 'source_sha256': hex_source, 'codegen_id': codegen.hex(),
            'module_sha256': hashlib.sha256(data).hexdigest(), 'native_sha256': '0' * 64,
            'published_sequence': 1}
(Path(cache) / (hex_source + '.current')).write_text(json.dumps(manifest))
print(hex_source)
