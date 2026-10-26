#!/usr/bin/env python3
"""Audit actual compact TU extraction; never authorize the output for execution."""

import json
import os
from pathlib import Path
import resource
import signal
import struct
import subprocess
import sys


def image(path):
    data = path.read_bytes()
    fields = struct.unpack_from('<14Q', data, 24)
    entry, bias, guest, nguest, code, ncode, tb, ntb, rel, nrel, pcmap, nmap, tu, ntu = fields
    return dict(data=data, bias=bias, code=data[code:code + ncode],
                guest=data[guest:guest + nguest],
                tbs=list(struct.iter_unpack('<QQIII2HI2HIII4x', data[tb:tb + ntb * 56])),
                rels=list(struct.iter_unpack('<Qq6I2Q2I', data[rel:rel + nrel * 64])),
                maps=list(struct.iter_unpack('<QQQII', data[pcmap:pcmap + nmap * 32])),
                tus=list(struct.iter_unpack('<QQQIIQII', data[tu:tu + ntu * 48])))


def main():
    latc, exports, plans, work = (Path(p).resolve() for p in sys.argv[1:5])
    work.mkdir()
    records = []

    def run(args, success=True, write_failure=False):
        def limit():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (16, 16))

        result = subprocess.run(list(map(str, args)), capture_output=True,
                                timeout=120, preexec_fn=limit if write_failure else None)
        index = len(records)
        (work / f'{index}.stdout').write_bytes(result.stdout)
        (work / f'{index}.stderr').write_bytes(result.stderr)
        records.append(dict(command=list(map(str, args)), rc=result.returncode))
        (work / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
        assert (result.returncode == 0) == success, records[-1] | {'stderr': result.stderr.decode()}
        return result

    for option in (0, 1):
        source = exports / f'{option}-2.native'
        remove = plans / f'{option}-{1-option}.tbset'
        output = work / f'{option}.native'
        run([latc, 'extract-native-tus', source, remove, '-o', output])
        audited = run([latc, 'audit-native-tu-references', output])
        assert b'movement_certified=false' in audited.stdout
        audited = run([latc, 'audit-native-tu-execution', output])
        assert b'movement_certified=false' in audited.stdout
        assert b'entries=2048\n' in audited.stdout
        old, new = image(source), image(output)
        removed = {rva for rva, _, _ in struct.iter_unpack('<QII', remove.read_bytes()[64:])}
        kept = [tb for tb in old['tbs'] if tb[0] - old['bias'] not in removed]
        assert len(kept) == len(new['tbs']) == 2048
        assert len(new['tus']) == 2048 and len(new['code']) < len(old['code'])
        assert new['guest'] == old['guest']
        for before, after in zip(kept, new['tbs']):
            assert before[:1] + before[2:-1] == after[:1] + after[2:-1]
            old_tu, new_tu = old['tus'][before[-1]], new['tus'][after[-1]]
            assert old_tu[1] == new_tu[1] and old_tu[3:] == new_tu[3:]
            assert old_tu[2] - old_tu[0] == new_tu[2] - new_tu[0]
            assert old['code'][old_tu[0]:old_tu[0] + old_tu[1]] == new['code'][new_tu[0]:new_tu[0] + new_tu[1]]
        kept_ranges = [(old['tus'][tb[-1]], new['tus'][ntb[-1]])
                       for tb, ntb in zip(kept, new['tbs'])]
        expected_rels, expected_maps = [], []
        for old_tu, new_tu in kept_ranges:
            shift = new_tu[0] - old_tu[0]
            for record in old['rels']:
                if old_tu[0] <= record[0] < old_tu[0] + old_tu[1]:
                    assert not record[6] and record[2] != 5
                    expected_rels.append((record[0] + shift,) + record[1:])
            for record in old['maps']:
                if old_tu[0] <= record[1] < old_tu[0] + old_tu[1]:
                    expected_maps.append((record[0], record[1] + shift, record[2] + shift) + record[3:])
        assert sorted(expected_rels) == sorted(new['rels'])
        assert expected_maps == new['maps']
        raw = new['data']
        assert struct.unpack_from('<I', raw, 16)[0] & 64
        size = struct.unpack_from('<I', raw, 272)[0]
        assert raw[-size:] == old['data'][-size:]
        result = run([latc, 'emit-aot-v2', output, work / f'forbidden-{option}'], False)
        assert b'not authorized for modules' in result.stderr
        result = run([latc, 'mark-native-x86', output], False)
        assert b'configuration replay cannot be marked executable' in result.stderr
        for bad in (output, work / f'link-{option}', work / f'fifo-{option}'):
            if bad.name.startswith('link-'):
                bad.symlink_to(output)
            elif bad.name.startswith('fifo-'):
                os.mkfifo(bad)
            run([latc, 'extract-native-tus', source, remove, '-o', bad], False)
        assert output.read_bytes() == raw
        failed = work / f'failed-{option}'
        run([latc, 'extract-native-tus', source, remove, '-o', failed], False, True)
        assert not failed.exists()
        # Empty removal after compaction is deterministic and does not grow code.
        again = work / f'{option}-again.native'
        run([latc, 'extract-native-tus', output, plans / f'{option}-{option}.tbset', '-o', again])
        assert again.read_bytes() == raw
        covered = {site + i * 4 for site, addend, kind, target, slots, *rest in new['rels']
                   for i in range(slots)}
        site = next(site for start, length, end, *rest in new['tus']
                    for site in range(start, end, 4) if site not in covered)
        damaged = bytearray(raw)
        code_offset = struct.unpack_from('<Q', raw, 56)[0]
        struct.pack_into('<I', damaged, code_offset + site, 0x1a000004)
        corrupted = work / f'{option}-unrecorded-address.native'
        corrupted.write_bytes(damaged)
        run([latc, 'inspect-native', corrupted])
        rejected = work / f'{option}-rejected.native'
        result = run([latc, 'extract-native-tus', corrupted,
                      plans / f'{option}-{option}.tbset', '-o', rejected], False)
        assert b'unsupported TU PC-relative address' in result.stderr
        assert not rejected.exists()
        # Reference scanning alone permits a raw JIRL. The entry-reachable
        # execution audit must refuse it before creating extracted output.
        site = next(tb[1] for tb in new['tbs'] if tb[1] not in covered)
        damaged = bytearray(raw)
        struct.pack_into('<I', damaged, code_offset + site, 0x4c000160)
        corrupted = work / f'{option}-unknown-transfer.native'
        corrupted.write_bytes(damaged)
        run([latc, 'audit-native-tu-references', corrupted])
        result = run([latc, 'extract-native-tus', corrupted,
                      plans / f'{option}-{option}.tbset', '-o', rejected], False)
        assert b'unresolved TU indirect transfer' in result.stderr
        assert not rejected.exists()
    print('test-native-tu-extract-real: PASS 2048 retained TUs/bytes/maps/relocations/quarantine/output')


if __name__ == '__main__':
    main()
