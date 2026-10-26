#!/usr/bin/env python3
"""Audit real discovery plans, rechunk identity and corrupt-plan refusal."""
import configparser
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

HEADER = struct.Struct('<8sII32sQQ')
KEY = struct.Struct('<QII')


def main():
    latc, guest = map(lambda p: str(Path(p).resolve()), sys.argv[1:3])
    with tempfile.TemporaryDirectory(prefix='latc-tbplan-') as temp:
        root = Path(temp)
        data = Path(guest).read_bytes()
        entry = struct.unpack_from('<Q', data, 24)[0]
        phoff = struct.unpack_from('<Q', data, 32)[0]
        phsize, phnum = struct.unpack_from('<HH', data, 54)
        base = min(struct.unpack_from('<Q', data, phoff + i * phsize + 16)[0]
                   for i in range(phnum)
                   if struct.unpack_from('<I', data, phoff + i * phsize)[0] == 1)
        source = root / 'input.tbset'
        source.write_bytes(HEADER.pack(b'LATTBKS\0', 1, 64,
            hashlib.sha256(data).digest(), 1, 17) + KEY.pack(entry-base, 3, 0))
        env = {**os.environ, 'LATC_TBSET_SELECTION': 'bounded',
               'LATC_TBSET_CLOSURE_LIMIT': '1'}
        for mode in ('exact', 'exact-static'):
            bundle = root / (mode + '.bundle')
            subprocess.run([latc, 'compile', guest, '-o', bundle,
                '--runner', guest, '--tbset', source], check=True,
                env={**env, 'LATC_TBSET_SELECTION': mode,
                     'LATC_TBSET_EXPAND_FUNCTIONS': '1'})
            info = json.loads(subprocess.check_output(
                [latc, 'inspect', '--json', bundle], text=True))
            assert info['functions'] == info['edges'] == 0, info
            assert info['tbs'] == info['selected_tbs'] == 1, info
            # Parse the serialized record as well as the reported counts.
            content = bundle.read_bytes()
            cfg_offset = 2 * len(data)
            header = struct.unpack_from('<8sII5Q', content, cfg_offset)
            assert header[:3] == (b'LATCCFG1', 5, 56)
            assert header[3:6] == (0, 1, 0)
            assert header[6] > 0 and header[7] == 0
            tb_offset = cfg_offset + 56 + 16 * header[6]
            tb = struct.unpack_from('<6QII', content, tb_offset)
            assert tb == (entry, entry+1, entry, 0, 0, 1, 0, 7), tb
        invalid = root / 'invalid.tbset'
        invalid.write_bytes(HEADER.pack(b'LATTBKS\0', 1, 64,
            hashlib.sha256(data).digest(), 1, 17) + KEY.pack(0, 3, 0))
        for mode in ('exact', 'exact-static'):
            command = [latc, 'compile', guest, '-o', root/'invalid.bundle',
                       '--runner', guest, '--tbset', invalid]
            result = subprocess.run(command, capture_output=True,
                env={**env, 'LATC_TBSET_SELECTION': mode})
            assert result.returncode and b'outside executable' in result.stderr
            subprocess.run(command + ['--tbset-ignore-outside-exec'], check=True,
                env={**env, 'LATC_TBSET_SELECTION': mode})
        identities = []
        for batch, budget in ((1, 1), (3, 7), (65536, 20000)):
            plan = root / f'plan-{batch}'
            subprocess.run([latc, 'plan-tbset', guest, source, plan,
                '--batch-size', str(batch), '--work-budget', str(budget)], env=env, check=True)
            config = configparser.ConfigParser()
            config.read(plan / 'plan.ini')
            identities.append(config['plan']['identity'])
            listing = subprocess.check_output([latc, 'list-tbplan', guest, plan], text=True)
            modes = set()
            keys = [[], []]
            for row in listing.splitlines():
                mode, name = row.split()
                modes.add(mode)
                contents = (plan/name).read_bytes()
                header = HEADER.unpack_from(contents)
                assert 0 < header[4] <= batch and header[5] == 17
                keys[mode == 'exact-static'].extend(KEY.iter_unpack(contents[64:]))
            assert modes == {'exact', 'exact-static'}
            assert keys[0] == [(entry-base, 3, 0)]
            assert len(keys[1]) > 1
            for group in keys:
                assert sorted(set(group)) == group
        assert len(set(identities)) == 1
        link = root/'guest-link'
        link.symlink_to(guest)
        subprocess.run([latc, 'plan-tbset', link, source, root/'symlink-plan'], env=env, check=True)
        subprocess.run([latc, 'list-tbplan', link, root/'symlink-plan'],
                       check=True, capture_output=True)
        # Undefined symbols can contribute RVA0; module bundle preparation has
        # always ignored non-executable input keys rather than translating them.
        invalid_key = (0, 3, 0)
        original = source.read_bytes()
        source.write_bytes(HEADER.pack(b'LATTBKS\0', 1, 64,
            hashlib.sha256(data).digest(), 2, 17) + KEY.pack(*invalid_key) + original[64:])
        subprocess.run([latc, 'plan-tbset', guest, source, root/'outside-plan'], env=env, check=True)
        outside = configparser.ConfigParser()
        outside.read(root/'outside-plan/plan.ini')
        assert outside['plan']['identity'] == identities[0]
        source.write_bytes(original)
        original = root/'plan-3'
        for kind in ('missing', 'truncated', 'writable', 'symlink', 'incomplete',
                     'identity', 'build', 'source', 'reordered', 'duplicate'):
            broken = root/kind
            shutil.copytree(original, broken)
            shard = sorted(broken.glob('*.tbset'))[-1]
            if kind == 'missing': shard.unlink()
            elif kind == 'truncated':
                shard.chmod(0o600)
                shard.write_bytes(shard.read_bytes()[:-1])
                shard.chmod(0o400)
            elif kind == 'writable': shard.chmod(0o600)
            elif kind == 'symlink':
                shard.unlink()
                shard.symlink_to(sorted(original.glob('*.tbset'))[-1])
            else:
                path = broken/'plan.ini'
                config = configparser.ConfigParser()
                config.read(path)
                if kind == 'incomplete': config['plan']['complete'] = 'false'
                elif kind in ('identity', 'build', 'source'): config['plan'][kind] = '0'*64
                elif kind == 'reordered': config['shard0']['mode'] = 'exact-static'
                elif kind == 'duplicate': config['shard1']['name'] = config['shard0']['name']
                path.chmod(0o600)
                with path.open('w') as stream: config.write(stream)
                path.chmod(0o400)
            result = subprocess.run([latc, 'list-tbplan', guest, broken], capture_output=True)
            assert result.returncode and not result.stdout, kind
        sentinel = root/'exists'
        sentinel.mkdir()
        (sentinel/'keep').write_text('keep')
        assert subprocess.run([latc, 'plan-tbset', guest, source, sentinel],
                              env=env, capture_output=True).returncode
        assert (sentinel/'keep').read_text() == 'keep'
    print('test-tbplan: PASS')


if __name__ == '__main__':
    main()
