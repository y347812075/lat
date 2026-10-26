#!/usr/bin/env python3
"""Keep native translation and final module selection in the same mode."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    script = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix='latc-module-environment-') as temp:
        work = Path(temp)
        shutil.copy2(script, work / script.name)
        for name, body in (
            ('compile-native-image.sh',
             'test "$1" = --module\nshift\n'
             'if [ "$1" = --static-tbset ]; then shift; fi\n'
             'printf native >"$4"\n'),
            ('link-aot-v2-module.sh', 'printf module >"$4"\n'),
        ):
            helper = work / name
            helper.write_text(
                '#!/bin/sh\nset -eu\n'
                'printf "%s:%s:%s\\n" "' + name + '" '
                '"${LATC_TBSET_SELECTION-unset}" '
                '"${LATC_TBSET_CLOSURE_LIMIT-unset}" >>"$ENV_LOG"\n' + body)
            helper.chmod(0o700)
        latc = work / 'latc'
        latc.write_text('#!/bin/sh\nexit 0\n')
        latc.chmod(0o700)
        for selection, limit in ((None, None), ('cfg', '0'),
                                 ('bounded', '17'), ('', '')):
            for mode in ('explicit', 'static', 'implicit'):
                env = dict(os.environ)
                for key in ('LATC_TBSET_SELECTION', 'LATC_TBSET_CLOSURE_LIMIT',
                            'LATC_NATIVE_BASE', 'LATC_NATIVE_OUTPUT'):
                    env.pop(key, None)
                if selection is not None:
                    env['LATC_TBSET_SELECTION'] = selection
                if limit is not None:
                    env['LATC_TBSET_CLOSURE_LIMIT'] = limit
                log = work / 'environment.log'
                log.write_text('')
                env.update(TMPDIR=str(work), ENV_LOG=str(log))
                args = ['sh', str(work / script.name)]
                if mode == 'static':
                    args.append('--static-tbset')
                args.extend([str(latc), 'runner', 'guest', 'runtime',
                             str(work / 'module.so')])
                if mode != 'implicit':
                    args.append('input.tbset')
                subprocess.run(args, env=env, check=True)
                expected = (f'{selection if selection is not None else "bounded"}:'
                            f'{limit if limit is not None else "20000"}')
                assert log.read_text().splitlines() == [
                    'compile-native-image.sh:' + expected,
                    'link-aot-v2-module.sh:' + expected,
                ]
                assert not list(work.glob('latc-aot-v2-compile.*'))
    print('test-module-selection-environment: PASS')


if __name__ == '__main__':
    main()
