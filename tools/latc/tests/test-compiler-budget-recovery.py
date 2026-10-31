#!/usr/bin/env python3
"""Observe bounded startup recovery and closed admission on isolated caches."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid


def run(prefix, guest, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = dict(os.environ, TMPDIR=str(Path.home() / 'tmp'),
               LD_LIBRARY_PATH=str(prefix / 'lib'))
    latcd = prefix / 'bin/latcd'
    keys = work / 'input.tbset'
    subprocess.run([sys.executable, str(Path(__file__).with_name('make-tbset.py')),
                    str(guest), str(keys)], env=env, check=True)

    def put(path, contents):
        path.write_text(contents)
        path.chmod(0o400)

    for mode in ('precise', 'missing', 'managed-missing', 'unsafe'):
        directory = work / mode
        cache = directory / 'cache'
        tasks, budgets = cache / '.gc/tasks', cache / '.gc/compiler-budgets'
        for path in (directory, cache, cache / '.tmp', cache / '.gc', tasks, budgets):
            path.mkdir(mode=0o700)
        source = cache / '.tmp/input'
        put(source, 'isolated input')
        for _ in range(320):
            task_id = str(uuid.uuid4())
            record = (f'[task]\nversion=1\nid={task_id}\nstate=BOUND\n'
                      f'source={"a" * 64}\nbuild_id={"b" * 64}\nenvironment_sha256={"c" * 64}\n')
            if mode == 'managed-missing':
                record = record.replace('version=1', 'version=3').replace(
                    'state=BOUND', 'state=PREPARED\nkind=MANAGED_COMPILER')
            for role, path in (('cache', cache), ('temporary', cache / '.tmp'), ('source', source)):
                st = path.stat()
                record += (f'[{role}]\ndevice={st.st_dev}\ninode={st.st_ino}\n'
                           f'size={st.st_size}\nmode={st.st_mode}\nuid={st.st_uid}\n'
                           f'mtime_sec={st.st_mtime_ns // 10**9}\nmtime_nsec={st.st_mtime_ns % 10**9}\n')
                if role == 'source':
                    record += 'name=input\ndirectory=temporary\n'
            record += (f'[output_native]\nname=native-{task_id}\n'
                       f'[output_module]\nname=module-{task_id}\n')
            task = tasks / (task_id + '.ini')
            put(task, record)
            if mode not in ('missing', 'managed-missing'):
                st, root = task.stat(), cache.stat()
                put(budgets / task.name,
                    f'[budget]\nversion=1\ntask_id={task_id}\n'
                    f'task_device={st.st_dev}\ntask_inode={st.st_ino}\n'
                    f'cache_device={root.st_dev}\ncache_inode={root.st_ino}\nbytes=4096\n')
        if mode == 'unsafe':
            # Encountered only in pass two, after the initial bounded budget batch.
            put(tasks / (str(uuid.uuid4()) + '.ini'), '[task]\nversion=9\n')
        socket, stats = directory / 's', directory / 'stats.json'
        command = [str(latcd), '--serve', '--socket', str(socket), '--cache-dir', str(cache),
                   '--latc', str(prefix / 'bin/latc'), '--runner', str(prefix / 'bin/latx-x86_64'),
                   '--runtime-dir', str(prefix / 'lib'), '--stats', str(stats)]
        with (directory / 'daemon.log').open('wb') as log:
            daemon = subprocess.Popen(command, env=env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 30
                while not stats.exists():
                    if daemon.poll() is not None:
                        break
                    assert time.monotonic() < deadline
                    time.sleep(.01)
                if not stats.exists():
                    assert mode in ('missing', 'managed-missing', 'unsafe'), mode
                    assert daemon.wait(timeout=10) != 0
                    if mode != 'unsafe':
                        assert b'capacity index invalid after compiler budget recovery' in (directory / 'daemon.log').read_bytes()
                    continue
                value = json.loads(stats.read_bytes())
                if value['compiler_budget_recovery_state'] == 0:
                    result = subprocess.run([str(latcd), '--submit', '--socket', str(socket),
                                             '--tbset', str(keys), str(guest)], env=env,
                                            capture_output=True, timeout=10)
                    # Recovery can finish between the stats read and the request.
                    if result.returncode != 0:
                        assert b'budget recovery' in result.stdout + result.stderr, result
                # Control requests stay responsive while the cursor advances.
                subprocess.run([str(latcd), '--flush-all', '--socket', str(socket)],
                               env=env, check=True, capture_output=True, timeout=2)
                while True:
                    value = json.loads(stats.read_bytes())
                    if value['compiler_budget_recovery_state'] != 0:
                        break
                    assert daemon.poll() is None and time.monotonic() < deadline
                    time.sleep(.02)
                assert value['compiler_budget_recovery_state'] == (-1 if mode == 'unsafe' else 1), value
                if mode == 'precise':
                    assert value['recovered_compiler_reserved_bytes'] == 320 * 4096, value
                    assert value['unknown_compiler_budget_tasks'] == 0, value
                    subprocess.run([str(latcd), '--submit', '--socket', str(socket),
                                    '--tbset', str(keys), str(guest)], env=env, check=True,
                                   capture_output=True, timeout=10)
                    subprocess.run([str(latcd), '--flush-source', '--socket', str(socket),
                                    str(guest)], env=env, check=True, capture_output=True, timeout=120)
                    assert list(cache.glob('*.current'))
                elif mode in ('missing', 'managed-missing'):
                    assert value['unknown_compiler_budget_tasks'] == 320, value
                else:
                    result = subprocess.run([str(latcd), '--submit', '--socket', str(socket),
                                             '--tbset', str(keys), str(guest)], env=env,
                                            capture_output=True, timeout=10)
                    assert result.returncode != 0 and b'budget recovery' in result.stdout + result.stderr
                if mode != 'precise':
                    assert not list(cache.glob('*.current'))
                daemon.terminate()
                assert daemon.wait(timeout=10) == 0
            finally:
                if daemon.poll() is None:
                    daemon.kill()
                    daemon.wait(timeout=10)
    print('test-compiler-budget-recovery: bounded/pending/control/precise/missing/managed-missing/unsafe PASS')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: test-compiler-budget-recovery.py PREFIX X86_GUEST NEW_WORKDIR')
    run(*(Path(value).resolve() for value in sys.argv[1:]))
