#!/usr/bin/env python3
"""Exercise the daemon's current manifest parser with bounded fixtures."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

daemon = sys.argv[1]
source = 'a' * 64
manifest = {'version': 2, 'module': source + '-1.so',
            'native': source + '-1.native', 'tbset': source + '-1.tbset',
            'source_sha256': source, 'codegen_id': 'b' * 64,
            'published_sequence': 1, 'module_sha256': 'c' * 64,
            'native_sha256': 'd' * 64}

with tempfile.TemporaryDirectory(prefix='latcd-manifest-', dir=os.environ['TMPDIR']) as tmp:
    path = Path(tmp) / (source + '.current')

    def check(raw, expected):
        path.write_text(raw)
        result = subprocess.run([daemon, '--test-current-manifest', tmp, source],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert (result.returncode == 0) == expected, (raw, result.stderr)

    check(json.dumps(manifest), True)
    old = dict(manifest)
    del old['module_sha256'], old['native_sha256']
    check(json.dumps(old), True)
    for field, value in [('source_sha256', 'e' * 64), ('codegen_id', 'bad'),
                         ('module_sha256', 'bad'), ('module', '../bad.so'),
                         ('published_sequence', 2**64), ('version', 3),
                         ('config_sha256', 'f' * 64)]:
        check(json.dumps(manifest | {field: value}), False)
    check(json.dumps(manifest)[:-1] + ', "version": 2}', False)
    check(json.dumps(manifest) + ' garbage', False)
print('test-current-manifest: PASS')
