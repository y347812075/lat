#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import tempfile

with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', str(Path.home() / 'tmp'))) as tmp:
    root = Path(tmp)
    config = root / 'client.env'
    config.write_text('LATX_AOT_V2=1\nLATX_AOT_V2_KEY_JOURNAL=1\n'
                      'LATX_AOT_V2_JOURNAL_BROKER=/broker\n'
                      'LATX_AOT_V2_JOURNAL_BROKER_UID=123\n')
    runner = root / 'runner'
    runner.write_text('#!/bin/sh\nenv\n')
    runner.chmod(0o755)
    source = Path('scripts/latx-x86_64-managed-wrapper.sh').read_text()
    source = source.replace('/etc/lat-aot-v2/client.env', str(config))
    source = source.replace('/usr/libexec/latc/latx-x86_64', str(runner))
    wrapper = root / 'wrapper'
    wrapper.write_text(source)

    def run(mode=None):
        env = {'PATH': os.environ['PATH']}
        if mode is not None:
            env['LATX_AOT_V2'] = mode
        result = subprocess.check_output(['sh', str(wrapper)], env=env, text=True)
        return dict(line.split('=', 1) for line in result.splitlines())

    managed = run()
    assert managed['LATX_AOT_V2'] == '1'
    assert managed['LATX_AOT_V2_KEY_JOURNAL'] == '1'
    assert managed['LATX_AOT_V2_JOURNAL_BROKER'] == '/broker'
    disabled = run('0')
    assert disabled['LATX_AOT_V2'] == '0'
    assert all(key not in disabled for key in ('LATX_AOT_V2_KEY_JOURNAL',
               'LATX_AOT_V2_JOURNAL_BROKER', 'LATX_AOT_V2_JOURNAL_BROKER_UID'))
print('test-managed-wrapper: PASS')
