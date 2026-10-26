#!/usr/bin/env python3
"""Verify complete constant objects in real AES exports and merged images."""

import json
import os
from pathlib import Path
import struct
import subprocess
import sys


def aes_tables():
    def multiply(a, b):
        result = 0
        for _ in range(8):
            if b & 1:
                result ^= a
            a = ((a << 1) ^ (0x11b if a & 128 else 0)) & 255
            b >>= 1
        return result

    te, last = bytearray(), bytearray()
    for value in range(256):
        inverse = 0 if value == 0 else 1
        for _ in range(254):
            inverse = multiply(inverse, value)
        s = inverse ^ 0x63
        for shift in (1, 2, 3, 4):
            s ^= ((inverse << shift) | (inverse >> (8 - shift))) & 255
        two, three = multiply(s, 2), multiply(s, 3)
        te.extend((two, s, s, three, three, two, s, s,
                   s, three, two, s, s, s, three, two))
        for shift in (0, 8, 16, 24):
            last.extend(struct.pack('<I', s << shift))
    return sorted((bytes(te), bytes(last)))


def main():
    prefix, guest, keys, work = (Path(p).resolve() for p in sys.argv[1:5])
    work.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(('LAT', 'SAVE_XMM'))}
    env.update(HOME=str(work), TMPDIR=str(work), LD_LIBRARY_PATH=str(prefix / 'lib'),
               LATC_AOT_THREADS='1', LATC_TBSET_SELECTION='cfg')
    records = []

    def run(args, extra=None, success=True):
        args = list(map(str, args))
        result = subprocess.run(args, env=env | (extra or {}), capture_output=True,
                                text=True, timeout=180)
        i = len(records)
        (work / f'{i}.stdout').write_text(result.stdout)
        (work / f'{i}.stderr').write_text(result.stderr)
        records.append(dict(command=args, environment=extra or {}, rc=result.returncode))
        (work / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
        assert (result.returncode == 0) == success, records[-1] | dict(stderr=result.stderr)
        return result

    def objects(path):
        data = path.read_bytes()
        assert struct.unpack_from('<II', data, 8) == (11, 280)
        code, code_size = struct.unpack_from('<QQ', data, 56)
        rel, count = struct.unpack_from('<QQ', data, 88)
        result = {}
        for record in struct.iter_unpack('<Qq6I2Q2I', data[rel:rel + count * 64]):
            site, addend, kind, target, slots, suffix, physical, padding, base, size, align, flags = record
            if kind != 5:
                assert (base, size, align, flags) == (0, 0, 0, 0)
                continue
            assert flags == 1 and align == 32 and base % align == 0
            assert base <= addend < base + size <= code_size
            assert suffix == base + size - addend
            assert (target, physical) == (0, 0) and slots in (2, 3)
            value = data[code + base:code + base + size]
            assert len(value) == size and any(value), 'missing complete AES table'
            result.setdefault((base, size), []).append((addend - base, value))
        assert result, 'AES fixture emitted no constant object'
        return result

    for mode in ('default', 'vpaes'):
        native = work / f'{mode}.native'
        extra = {'LATC_NATIVE_IMAGE_OUT': str(native)}
        query = [prefix / 'bin/latx-x86_64']
        if mode == 'vpaes':
            query += ['-latx-vpaes', '1']
        snapshot = work / f'{mode}.config'
        info = json.loads(run(query + ['--latc-translation-config-native',
            '--latc-translation-config-out', snapshot, guest], {'LATX_AOT_V2': '1'}).stdout)
        assert bool(info['values']['vpaes']) == (mode == 'vpaes')
        extra['LATC_TRANSLATION_CONFIG_FROM'] = str(snapshot)
        run([prefix / 'libexec/latc/scripts/compile-aot.sh', prefix / 'bin/latc',
             prefix / 'bin/latx-x86_64', guest, work / 'unused', keys], extra)
        run([prefix / 'bin/latc', 'inspect-native', native])
        original = objects(native)
        sizes = sorted(size for base, size in original)
        if mode == 'default':
            assert sizes == [4096, 4096], sizes
            assert sorted(refs[0][1] for refs in original.values()) == aes_tables()
        else:
            assert sizes in ([144], [288]), sizes
        assert any(len(refs) > 1 for refs in original.values()), 'fixture lost shared references'
        merged = work / f'{mode}-merged.native'
        run([prefix / 'bin/latc', 'merge-native', native, native, '-o', merged])
        combined = objects(merged)
        assert len(combined) == len(original) * 2
        assert sorted(v for group in combined.values() for _, v in group) == sorted(
            [v for group in original.values() for _, v in group] * 2)
        code_size = struct.unpack_from('<Q', native.read_bytes(), 64)[0]
        shift = (code_size + 31) & ~31
        for (base, size), refs in original.items():
            assert combined[(base, size)] == refs
            assert combined[(base + shift, size)] == refs
        # Remove one whole physical half of a real merged image. Give only its
        # guest keys distinct identities; physical bytes/relocations stay real.
        # This is a compaction fixture, not a runnable guest/config migration.
        raw = bytearray(merged.read_bytes())
        tb, count = struct.unpack_from('<QQ', raw, 72)
        first, second = [], []
        for i in range(count):
            record = bytearray(raw[tb + i * 56:tb + (i + 1) * 56])
            if struct.unpack_from('<Q', record, 8)[0] < shift:
                first.append((i, record))
            else:
                second.append((i, record))
        assert first and len(first) == len(second)
        replacement = []
        for i, record in first:
            replacement.append((i, record))
        for i, record in second:
            struct.pack_into('<Q', record, 0, struct.unpack_from('<Q', record)[0] + 0x100000000)
            replacement.append((i, record))
        replacement.sort(key=lambda item: struct.unpack_from('<Q', item[1])[0])
        index_map = {old: new + 1 for new, (old, record) in enumerate(replacement)}
        for i, (_, record) in enumerate(replacement):
            raw[tb + i * 56:tb + (i + 1) * 56] = record
        rel, nrel = struct.unpack_from('<QQ', raw, 88)
        for i in range(nrel):
            physical = struct.unpack_from('<I', raw, rel + i * 64 + 32)[0]
            if physical:
                struct.pack_into('<I', raw, rel + i * 64 + 32, index_map[physical - 1])
        altered = work / f'{mode}-extract-input.native'
        altered.write_bytes(raw)
        removal = bytearray(64)
        struct.pack_into('<8sII', removal, 0, b'LATTBKS\0', 1, 64)
        removal[16:48] = raw[136:168]
        struct.pack_into('<Q', removal, 48, len(first))
        bias = struct.unpack_from('<Q', raw, 32)[0]
        for _, record in first:
            pc = struct.unpack_from('<Q', record)[0]
            removal.extend(struct.pack('<QII', pc - bias, 3, 0))
        removal_path = work / f'{mode}-remove.tbset'
        removal_path.write_bytes(removal)
        compact = work / f'{mode}-compact.native'
        run([prefix / 'bin/latc', 'extract-native-tus', altered, removal_path, '-o', compact])
        compact_objects = objects(compact)
        assert len(compact_objects) == len(original)
        assert sorted(v for group in compact_objects.values() for _, v in group) == sorted(
            v for group in original.values() for _, v in group)
        assert struct.unpack_from('<Q', compact.read_bytes(), 64)[0] < struct.unpack_from('<Q', raw, 64)[0]
        rejected = run([prefix / 'bin/latc', 'emit-aot-v2', native,
                        work / f'{mode}-forbidden'], success=False)
        assert 'not authorized for modules' in rejected.stderr
        run([prefix / 'bin/latx-x86_64', '-latx-vpaes', str(int(mode == 'vpaes')), guest],
            {'LATX_AOT': '0', 'LATX_AOT_V2': '0', 'LATC_DISABLE_PRETRANSLATE': '1'})
    print('real native complete constant objects passed')


if __name__ == '__main__':
    main()
