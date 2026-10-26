#!/usr/bin/env python3
"""Query real option resolution without running the guest or preparing caches."""

import json
import hashlib
import os
from pathlib import Path
import struct
import re
import resource
import signal
import subprocess
import sys
import tempfile


def main():
    translator = str(Path(sys.argv[1]).resolve())
    abi = sys.argv[2]
    schema = (Path(__file__).resolve().parents[2] /
              'tools/latc/aot-v2/include/lat-translation-config.h').read_text()
    fields = re.findall(r'\bX\([A-Z0-9_]+, ([a-z0-9_]+)\)', schema)
    assert fields and len(fields) == len(set(fields))
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(('LAT', 'SAVE_XMM', 'XDG_'))}
    temporary_root = Path.home() / 'tmp'
    temporary_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='latx-config-',
                                     dir=temporary_root) as temporary:
        root = Path(temporary)
        home = root / 'home'
        (home / '.config').mkdir(parents=True)
        environment.update(HOME=str(home), TMPDIR=str(root))
        guest = root / 'guest'
        ident = b'\x7fELF' + bytes([2 if abi == 'x86_64' else 1, 1, 1, 0]) + bytes(8)
        if abi == 'x86_64':
            # No PT_LOAD: executing this file must fail, unlike a config query.
            header = struct.pack('<16sHHIQQQIHHHHHH', ident, 2, 62, 1,
                                 0x400000, 64, 0, 0, 64, 56, 0, 0, 0, 0)
        else:
            header = struct.pack('<16sHHIIIIIHHHHHH', ident, 2, 3, 1,
                                 0x8048000, 52, 0, 0, 52, 32, 0, 0, 0, 0)
        guest.write_bytes(header)
        config_file = home / '.config' / f'latx-{abi}.conf'
        config_file.write_text('LATX_CVT_OPT=0\nLATX_ROUNDING_OPT=0\n'
                               '[guest]\nLATX_CVT_OPT=1\n')

        def query(*options, overrides=None, path=guest, success=True):
            env = environment | (overrides or {})
            args = [translator, '--latc-translation-config', *options]
            if path is not None:
                args.append(str(path))
            result = subprocess.run(args, env=env, capture_output=True,
                                    text=True, timeout=30)
            if not success:
                assert result.returncode != 0, result
                return
            assert result.returncode == 0, (args, result.stdout, result.stderr)
            info = json.loads(result.stdout)
            assert info['schema_version'] == 1
            assert info['compatibility_complete'] is False
            assert info['native_replay_domain'] is False
            assert info['guest_abi'] == abi
            assert len(info['build_id']) == 64
            assert len(info['configuration_sha256']) == 64
            assert set(info['values']) == set(fields)
            assert all(type(value) is int for value in info['values'].values())
            assert all(len(value) == 16 and int(value, 16) >= 0
                       for value in info['x86_features'])
            count = len(info['x86_features'])
            header = struct.pack('<8s6I', b'LATCFG1\0', 1,
                                 64 + 8 * (len(fields) + count), 0,
                                 1 if abi == 'x86_64' else 2, len(fields), count)
            body = b''.join(struct.pack('<q', info['values'][field])
                            for field in fields)
            body += b''.join(struct.pack('<Q', int(value, 16))
                             for value in info['x86_features'])
            assert hashlib.sha256(header + body).hexdigest() == info['configuration_sha256']
            return info

        configured = query()

        def binary(info):
            count = len(info['x86_features'])
            data = struct.pack('<8s6I', b'LATCFG1\0', 1,
                               64 + 8 * (len(fields) + count),
                               int(info['compatibility_complete']),
                               1 if abi == 'x86_64' else 2, len(fields), count)
            data += bytes.fromhex(info['build_id'])
            data += b''.join(struct.pack('<q', info['values'][field])
                             for field in fields)
            return data + b''.join(struct.pack('<Q', int(value, 16))
                                   for value in info['x86_features'])

        replay = root / 'replay.config'
        replay.write_bytes(binary(configured))
        exported = root / 'exported.config'
        assert configured == query('--latc-translation-config-out', str(exported))
        assert exported.read_bytes() == binary(configured)
        assert exported.stat().st_mode & 0o777 == 0o600
        assert configured == query('--latc-translation-config-from', str(exported),
                                   overrides={'LATX_CVT_OPT': '0'})
        copied = root / 'copied.config'
        assert configured == query('--latc-translation-config-from', str(exported),
                                   '--latc-translation-config-out', str(copied),
                                   overrides={'LATX_CVT_OPT': '0'})
        assert copied.read_bytes() == exported.read_bytes()
        standalone = root / 'standalone.config'
        result = subprocess.run([translator, '--latc-translation-config-out',
                                 str(standalone), str(guest)], env=environment,
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == configured
        assert standalone.read_bytes() == binary(configured)
        sentinel = root / 'sentinel.config'
        sentinel.write_bytes(b'preserve existing output')
        output_link = root / 'output-link'
        output_link.symlink_to(sentinel)
        output_fifo = root / 'output-fifo'
        os.mkfifo(output_fifo)
        for path in (sentinel, output_link, output_fifo, root,
                     root / 'missing-parent' / 'snapshot'):
            query('--latc-translation-config-out', str(path), success=False)
        assert sentinel.read_bytes() == b'preserve existing output'
        assert output_link.is_symlink()
        assert output_fifo.is_fifo()
        query('--latc-translation-config-from', str(exported),
              '--latc-translation-config-out', str(exported), success=False)
        assert exported.read_bytes() == binary(configured)

        def limit_output():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (80, 80))

        failed_output = root / 'failed.config'
        result = subprocess.run([translator, '--latc-translation-config-out',
                                 str(failed_output), str(guest)], env=environment,
                                preexec_fn=limit_output, capture_output=True,
                                text=True, timeout=30)
        assert result.returncode != 0 and result.returncode != -signal.SIGXFSZ
        assert not failed_output.exists(), 'failed export left a partial snapshot'
        query('--runtime-info', '--latc-translation-config-out',
              str(root / 'conflicting.config'), success=False)
        assert not (root / 'conflicting.config').exists()
        query('--latc-translation-config-out', str(root / 'no-guest.config'),
              path=None, success=False)
        assert not (root / 'no-guest.config').exists()
        query('--latc-translation-config-out', str(root / 'no-source.config'),
              path=root / 'missing', success=False)
        assert not (root / 'no-source.config').exists()
        assert configured == query('--latc-translation-config-from', str(replay),
                                   overrides={'LATX_CVT_OPT': '0',
                                              'LATX_ROUNDING_OPT': '1'})
        assert configured['values']['cvt_opt'] == 1
        assert configured['values']['rounding_opt'] == 0
        disabled = query(overrides={'LATX_CVT_OPT': '0'})
        assert disabled['values']['cvt_opt'] == 0
        assert disabled['configuration_sha256'] != configured['configuration_sha256']
        assert configured == query('--latx-cvt-opt', '1',
                                   overrides={'LATX_CVT_OPT': '0'})
        assert disabled == query(overrides={'LATX_CVT_OPT': '0x0'})
        assert configured == query(overrides={'LATX_AOT_V2_REPORT': '1',
                                              'LATC_COMPILE_TIMING': '1'})
        other = root / 'other'
        other.write_bytes(header)
        assert query(path=other)['values']['cvt_opt'] == 0
        program = root / 'program'
        program.write_bytes(header)
        assert query(path=program)['values']['lative'] == 1
        assert configured == query('--latc-translation-config-from', str(replay),
                                   path=program)
        broken = root / 'broken.config'
        original = binary(configured)
        for payload in (original[:63], original[:-1], original + b'x',
                        original[:32] + bytes(32) + original[64:]):
            broken.write_bytes(payload)
            query('--latc-translation-config-from', str(broken), success=False)
        corrupted = bytearray(original)
        struct.pack_into('<q', corrupted, 64 + 8 * fields.index('cvt_opt'), 1 << 40)
        broken.write_bytes(corrupted)
        query('--latc-translation-config-from', str(broken), success=False)
        query('--latc-translation-config-from', str(broken),
              '--latc-translation-config-out', str(root / 'bad-replay.config'),
              success=False)
        assert not (root / 'bad-replay.config').exists()
        corrupted = bytearray(original)
        struct.pack_into('<q', corrupted, 64 + 8 * fields.index('host_scq'),
                         configured['values']['host_scq'] ^ 1)
        broken.write_bytes(corrupted)
        query('--latc-translation-config-from', str(broken), success=False)
        corrupted = bytearray(original)
        corrupted[-1] ^= 1
        broken.write_bytes(corrupted)
        query('--latc-translation-config-from', str(broken), success=False)
        corrupted = bytearray(original)
        struct.pack_into('<I', corrupted, 16, 1)
        broken.write_bytes(corrupted)
        query('--latc-translation-config-from', str(broken), success=False)
        query('--latc-translation-config-from', str(root), success=False)
        link = root / 'config-link'
        link.symlink_to(replay)
        query('--latc-translation-config-from', str(link), success=False)
        fifo = root / 'config-fifo'
        os.mkfifo(fifo)
        query('--latc-translation-config-from', str(fifo), success=False)
        result = subprocess.run([translator, '--latc-translation-config-from',
                                 str(replay), str(guest)], env=environment,
                                capture_output=True, text=True, timeout=30)
        assert result.returncode != 0
        assert 'diagnostic-only' in result.stderr
        query('--runtime-info', '--latc-translation-config-from', str(replay),
              success=False)
        if abi == 'x86_64':
            cache = root / 'must-not-be-created'
            enabled = query(overrides={'LATX_AOT_V2': '1',
                                       'LATX_AOT_V2_CACHE_DIR': str(cache)})
            assert enabled['values']['legacy_aot'] == 0
            assert enabled['values']['parallel'] == 1
            assert not cache.exists()
            aot_snapshot = root / 'aot.config'
            assert enabled == query('--latc-translation-config-out', str(aot_snapshot),
                                    overrides={'LATX_AOT_V2': '1',
                                               'LATX_AOT_V2_CACHE_DIR': str(cache)})
            assert aot_snapshot.read_bytes() == binary(enabled)
            assert not cache.exists()
            assert not (home / '.cache').exists()
            assert not (home / '.local').exists()
            query(overrides={'LATX_AOT_V2': 'invalid'}, success=False)
            query('--latx-aot', '1', overrides={'LATX_AOT_V2': '1'},
                  success=False)
        query(path=None, success=False)
        query('--runtime-info', success=False)
        query('--not-an-option', success=False)
        query(path=root / 'missing', success=False)
        config_file.unlink()
        assert query()['values']['cvt_opt'] == 1
    print('effective translation configuration query passed')


if __name__ == '__main__':
    main()
