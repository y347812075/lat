#!/usr/bin/env python3
"""Exercise real native code generation under opposing effective options."""

import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import re
import hashlib
from tb_key_set import read_key_set, write_key_set_digest


def main():
    prefix, guest, keys, work = map(lambda p: Path(p).resolve(), sys.argv[1:5])
    work.mkdir()
    runner = prefix / 'bin/latx-x86_64'
    latc = prefix / 'bin/latc'
    script = prefix / 'libexec/latc/scripts/compile-aot.sh'
    native_script = prefix / 'libexec/latc/scripts/compile-native-image.sh'
    env = {k: v for k, v in os.environ.items() if not k.startswith(('LAT', 'SAVE_XMM'))}
    home = work / 'home'
    (home / '.config').mkdir(parents=True)
    (home / '.config/latx-x86_64.conf').write_text('LATX_CVT_OPT=0\n[guest]\nLATX_CVT_OPT=1\n')
    env.update(HOME=str(home), TMPDIR=str(work), LD_LIBRARY_PATH=str(prefix / 'lib'),
               LATC_AOT_THREADS='1', LATC_TBSET_SELECTION='exact')
    records = []

    def run(args, extra=None, success=True):
        args = list(map(str, args))
        result = subprocess.run(args, env=env | (extra or {}), capture_output=True,
                                text=True, timeout=120)
        i = len(records)
        (work / f'{i:02d}.stdout').write_text(result.stdout)
        (work / f'{i:02d}.stderr').write_text(result.stderr)
        records.append({'command': args, 'environment': extra or {}, 'rc': result.returncode})
        (work / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
        assert (result.returncode == 0) == success, records[-1] | {'stderr': result.stderr}
        return result

    def content(path):
        data = path.read_bytes()
        code, size, table, count, rel, nrel = struct.unpack_from('<6Q', data, 56)
        # Canonicalize only relocation windows; retain all relative metadata.
        normalized = bytearray(data[code:code + size])
        relocations = data[rel:rel + nrel * 64]
        for record in struct.iter_unpack('<Qq6I2Q2I', relocations):
            offset, addend, kind, target, slots, reserved, physical, padding = record[:8]
            normalized[offset:offset + slots * 4] = bytes(slots * 4)
        return bytes(normalized), relocations, data[table:table + count * 56]

    info = {}
    has_kzt = 'LATX_KZT' in run([runner, '--help']).stdout
    if has_kzt:
        rejected_kzt = work / 'kzt.config'
        rejected = run([runner, '--latc-translation-config-native',
             '--latc-translation-config-out', rejected_kzt, guest],
            {'LATX_AOT_V2': '1', 'LATX_KZT': '1'}, success=False)
        assert 'unsupported native configuration export domain' in rejected.stderr
        assert not rejected_kzt.exists()
    for option in (0, 1):
        snapshot = work / f'config-{option}'
        result = run([runner, '--latc-translation-config-native',
                      '--latc-translation-config-out', snapshot, guest],
                     {'LATX_AOT_V2': '1', 'LATX_CVT_OPT': str(option)})
        info[option] = json.loads(result.stdout)
        assert info[option]['values']['cvt_opt'] == option
        raw = snapshot.read_bytes()
        assert struct.unpack_from('<I', raw, 16)[0] == 2
        assert info[option]['native_replay_domain'] is True
        assert info[option]['configuration_sha256'] == hashlib.sha256(raw[:32] + raw[64:]).hexdigest()
        for replay in (False, True):
            output = work / f'{option}-{replay}.native'
            extra = {'LATX_CVT_OPT': str(1 - option if replay else option),
                     'LATC_NATIVE_IMAGE_OUT': str(output)}
            if replay:
                extra['LATC_TRANSLATION_CONFIG_FROM'] = str(snapshot)
            run([script, latc, runner, guest, work / 'unused', keys], extra)
            inspection = json.loads(run([latc, 'inspect-native', '--json', output]).stdout)
            if replay:
                assert inspection['flags'] & 64
                assert inspection['translation_config_sha256'] != '0' * 64
                raw = snapshot.read_bytes()
                assert inspection['translation_config_sha256'] == hashlib.sha256(raw[:32] + raw[64:]).hexdigest()
                assert output.read_bytes().endswith(snapshot.read_bytes())
                assert content(output) == content(work / f'{option}-False.native')
                rejected = run([latc, 'emit-aot-v2', output, work / 'forbidden'], success=False)
                assert 'not authorized for modules' in rejected.stderr
                run([latc, 'mark-native-x86', output], success=False)
    assert content(work / '0-True.native')[0] != content(work / '1-True.native')[0]
    isolated = work / 'isolated.native'
    if has_kzt:
        run([native_script, '--config-replay', latc, runner, guest,
             work / 'kzt.native', keys],
            {'LATX_KZT': '2', 'LATC_TRANSLATION_CONFIG_FROM': str(work / 'config-0')},
            success=False)
        assert not (work / 'kzt.native').exists()
    run([native_script, '--config-replay', latc, runner, guest, isolated, keys],
        {'LATX_CVT_OPT': '1', 'LATC_TRANSLATION_CONFIG_FROM': str(work / 'config-0')})
    assert content(isolated) == content(work / '0-True.native')
    cli_isolated = work / 'cli-isolated.native'
    run([latc, 'compile-replay-native', guest, '-o', cli_isolated,
         '--runner', runner, '--tbset', keys, '--config', work / 'config-0'],
        {'LATX_CVT_OPT': '1', 'LATC_TRANSLATION_CONFIG_FROM': str(work / 'config-1')})
    assert content(cli_isolated) == content(isolated)
    assert cli_isolated.read_bytes().endswith((work / 'config-0').read_bytes())
    incremental = work / 'incremental.native'
    run([latc, 'compile-replay-native', guest, '-o', incremental,
         '--runner', runner, '--tbset', keys, '--config', work / 'config-0'],
        {'LATC_NATIVE_BASE': str(isolated)})
    run([latc, 'validate-replay-native', incremental, work / 'config-0', keys])
    no_compile = work / 'no-compile.native'
    run([native_script, '--config-replay', latc, work / 'nonexistent-runner', guest,
         no_compile, keys],
        {'LATC_NATIVE_BASE': str(isolated),
         'LATC_TRANSLATION_CONFIG_FROM': str(work / 'config-0')})
    assert no_compile.read_bytes() == isolated.read_bytes()
    run([native_script, '--config-replay', latc, runner, guest, isolated, keys],
        {'LATC_NATIVE_BASE': str(isolated),
         'LATC_TRANSLATION_CONFIG_FROM': str(work / 'config-0')}, success=False)
    assert isolated.read_bytes() == no_compile.read_bytes()
    static_keys = work / 'static.tbset'
    run([latc, 'emit-static-tbset', guest, '-o', static_keys])
    source_hash, _, requested = read_key_set(keys)
    extra_key = next(key for key in read_key_set(static_keys)[2] if key not in requested)
    expanded = work / 'expanded.tbset'
    write_key_set_digest(source_hash, expanded, requested + [extra_key])
    expanded_native = work / 'expanded.native'
    run([latc, 'compile-replay-native', guest, '-o', expanded_native,
         '--runner', runner, '--tbset', expanded, '--config', work / 'config-0'],
        {'LATC_NATIVE_BASE': str(isolated)})
    run([latc, 'validate-replay-native', expanded_native, work / 'config-0', expanded])
    assert json.loads(run([latc, 'inspect-native', '--json', expanded_native]).stdout)['tbs'] > \
        json.loads(run([latc, 'inspect-native', '--json', isolated]).stdout)['tbs']
    assert incremental.read_bytes().endswith((work / 'config-0').read_bytes())
    run([latc, 'emit-aot-v2', incremental, work / 'incremental-forbidden'], success=False)
    run([latc, 'compile-replay-native', guest, '-o', work / 'incompatible-base.native',
         '--runner', runner, '--tbset', keys, '--config', work / 'config-1'],
        {'LATC_NATIVE_BASE': str(isolated)}, success=False)
    assert not (work / 'incompatible-base.native').exists()
    run([latc, 'compile-replay-native', guest, '-o', work / 'no-config.native',
         '--runner', runner, '--tbset', keys], success=False)
    assert not (work / 'no-config.native').exists()
    source_hash, _, requested = read_key_set(keys)
    missing_keys = work / 'missing-keys.tbset'
    write_key_set_digest(source_hash, missing_keys, requested + [(0xfffffffffffffff0, 3)])
    delta = work / 'delta.tbset'
    result = run([latc, 'missing-replay-tbset', isolated, work / 'config-0',
                  missing_keys, guest, '-o', delta])
    assert 'missing_tb_keys=1' in result.stdout
    assert read_key_set(delta)[2] == [(0xfffffffffffffff0, 3)]
    run([latc, 'missing-replay-tbset', isolated, work / 'config-1', keys,
         guest, '-o', work / 'wrong-config-delta'], success=False)
    assert not (work / 'wrong-config-delta').exists()
    run([latc, 'missing-replay-tbset', isolated, work / 'config-0', keys,
         latc, '-o', work / 'wrong-guest-delta'], success=False)
    assert not (work / 'wrong-guest-delta').exists()
    missing_check = run([latc, 'validate-replay-native', isolated,
                         work / 'config-0', missing_keys], success=False)
    assert 'missing requested TB' in missing_check.stderr
    wrong_source = work / 'wrong-source.tbset'
    write_key_set_digest(bytes(32), wrong_source, requested)
    run([latc, 'validate-replay-native', isolated, work / 'config-0', wrong_source],
        success=False)
    run([latc, 'validate-replay-native', isolated, work / 'config-1', keys], success=False)
    run([latc, 'validate-replay-native', work / '0-False.native', work / 'config-0', keys], success=False)
    run([native_script, '--config-replay', latc, runner, guest, work / 'missing.native', keys],
        success=False)
    assert not (work / 'missing.native').exists()
    run([latc, 'merge-native', work / '0-True.native', work / '0-True.native',
         '-o', work / 'same.native'])
    assert (work / 'same.native').read_bytes().endswith((work / 'config-0').read_bytes())
    for other in ('1-True.native', '0-False.native'):
        run([latc, 'merge-native', work / '0-True.native', work / other,
             '-o', work / 'different.native'], success=False)
        assert not (work / 'different.native').exists()
    bundle = work / 'stage1'
    run([latc, 'compile', guest, '-o', bundle, '--runner', runner, '--tbset', keys])
    for label, extra in (
        ('no-emit', {'LATC_NATIVE_IMAGE_OUT': str(work / 'no-emit.native')}),
        ('no-nativeout', {'LATC_EMIT_AOT': '1'}),
    ):
        run([bundle], {'LATC_TRANSLATION_CONFIG_FROM': str(work / 'config-0')} | extra,
            success=False)
    assert not (work / 'no-emit.native').exists()
    for case, extra in (
        ('no-emit', {}),
        ('no-native', {'LATC_EMIT_AOT': '1'}),
        ('unbundled', {'LATC_EMIT_AOT': '1', 'LATC_NATIVE_IMAGE_OUT': str(work / 'bad.native')}),
    ):
        run([runner, guest], extra | {'LATC_TRANSLATION_CONFIG_FROM': str(work / 'config-0')}, success=False)
    ordinary = work / 'ordinary.config'
    run([runner, '--latc-translation-config-out', ordinary, guest], {'LATX_AOT_V2': '1'})
    for case, snapshot, extra in (
        ('old-domain', ordinary, {}),
        ('disabled', work / 'config-0', {'LATC_DISABLE_PRETRANSLATE': '1'}),
    ):
        output = work / f'bad-{case}.native'
        run([script, latc, runner, guest, work / 'unused', keys],
            {'LATC_TRANSLATION_CONFIG_FROM': str(snapshot),
             'LATC_NATIVE_IMAGE_OUT': str(output)} | extra, success=False)
        assert not output.exists()
    worker_env = {'LATX_AOT': '1', 'LATX_AOT_V2': '0',
                  'LATX_AOT_V2_AUTOSTART': '0', 'LATC_EMIT_AOT': '1',
                  'LATC_NAMED_GUEST': str(work / 'x86-guest'),
                  'LATC_TRANSLATION_CONFIG_FROM': str(work / 'config-0')}
    run([bundle], worker_env | {'LATC_NATIVE_IMAGE_OUT': str(work / 'direct.native')})
    assert content(work / 'direct.native') == content(work / '0-True.native')
    nonparallel = bytearray(bundle.read_bytes())
    footer = struct.Struct('<8sII11Q64s64s160s')
    fields = footer.unpack_from(nonparallel, len(nonparallel) - footer.size)
    assert fields[:3] == (b'LATCBND1', 4, footer.size)
    cfg = fields[6]
    header = struct.unpack_from('<8sII5Q', nonparallel, cfg)
    assert header[:3] == (b'LATCCFG1', 5, 56)
    tb_start = cfg + 56 + header[3] * 48 + header[6] * 16
    for i in range(header[4]):
        offset = tb_start + i * 56
        if struct.unpack_from('<Q', nonparallel, offset + 40)[0]:
            flags = struct.unpack_from('<I', nonparallel, offset + 52)[0]
            assert flags & 2
            struct.pack_into('<I', nonparallel, offset + 52, flags & ~2)
            break
    else:
        raise AssertionError('bundle has no selected TB')
    nonparallel_bundle = work / 'nonparallel-stage1'
    nonparallel_bundle.write_bytes(nonparallel)
    nonparallel_bundle.chmod(0o700)
    output = work / 'bad-keys.native'
    rejected = run([nonparallel_bundle],
                   worker_env | {'LATC_NATIVE_IMAGE_OUT': str(output)}, success=False)
    assert 'native replay requires parallel TB keys' in rejected.stderr
    assert not output.exists()
    schema = (Path(__file__).resolve().parents[1] /
              'aot-v2/include/lat-translation-config.h').read_text()
    fields = re.findall(r'\bX\([A-Z0-9_]+, ([a-z0-9_]+)\)', schema)
    original = (work / 'config-0').read_bytes()
    for field, value in (('legacy_aot', 1), ('parallel', 0), ('softfpu', 1),
                         ('jr_ra', 1), ('anonym', 1), ('host_scq',
                         info[0]['values']['host_scq'] ^ 1)):
        altered = bytearray(original)
        struct.pack_into('<q', altered, 64 + fields.index(field) * 8, value)
        snapshot = work / f'bad-{field}.config'
        snapshot.write_bytes(altered)
        output = work / f'bad-{field}.native'
        run([script, latc, runner, guest, work / 'unused', keys],
            {'LATC_TRANSLATION_CONFIG_FROM': str(snapshot),
             'LATC_NATIVE_IMAGE_OUT': str(output)}, success=False)
        assert not output.exists()
    for label, offset, value in (('build', 32, 0xff), ('cpu', len(original) - 1, 0xff)):
        altered = bytearray(original)
        altered[offset] ^= value
        snapshot = work / f'bad-{label}.config'
        snapshot.write_bytes(altered)
        output = work / f'bad-{label}.native'
        run([script, latc, runner, guest, work / 'unused', keys],
            {'LATC_TRANSLATION_CONFIG_FROM': str(snapshot),
             'LATC_NATIVE_IMAGE_OUT': str(output)}, success=False)
        assert not output.exists()
    for option in ({'LATX_SOFTFPU': '1'}, {'LATX_JRRA': '1'},
                   {'LATX_ANONYM': '1'}):
        output = work / f'unsupported-{len(records)}.config'
        run([runner, '--latc-translation-config-native',
             '--latc-translation-config-out', output, guest],
            {'LATX_AOT_V2': '1'} | option, success=False)
        assert not output.exists()
    native = (work / '0-True.native').read_bytes()
    for label, mutate in (
        ('digest', lambda b: b.__setitem__(240, b[240] ^ 1)),
        ('snapshot', lambda b: b.__setitem__(-1, b[-1] ^ 1)),
        ('projection', lambda b: struct.pack_into('<I', b, 276, 2)),
        ('size', lambda b: struct.pack_into('<I', b, 272, 0xffffffff)),
        ('tb-flags', lambda b: struct.pack_into('<I', b,
                    struct.unpack_from('<Q', b, 72)[0] + 20, 1)),
    ):
        corrupted = bytearray(native)
        mutate(corrupted)
        path = work / f'corrupt-{label}.native'
        path.write_bytes(corrupted)
        run([latc, 'inspect-native', path], success=False)
    print('test-native-config-replay: PASS')


if __name__ == '__main__':
    main()
