#!/usr/bin/env python3
"""Exercise cache-domain identity and real daemon/runner validation."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(prefix, guest, work):
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    cache, socket, stats = work / 'cache', work / 'latcd.sock', work / 'stats.json'
    cache.mkdir(mode=0o700)
    env = dict(os.environ, TMPDIR=str(Path.home() / 'tmp'),
               LD_LIBRARY_PATH=str(prefix / 'lib'))
    latcd = prefix / 'bin/latcd'

    def gc(mode):
        return subprocess.run([str(latcd), 'gc', mode, '--cache-dir', str(cache)],
            env=env, capture_output=True, text=True, timeout=20)

    runner = prefix / 'bin/latx-x86_64'
    full = work / 'full.tbset'
    subprocess.run([str(prefix / 'bin/latc'), 'emit-static-tbset', str(guest),
                    '-o', str(full)], env=env, check=True, timeout=120)
    bootstrap = [str(latcd), '--once', '--socket', str(socket), '--cache-dir', str(cache),
                 '--latc', str(prefix / 'bin/latc'), '--runner', str(runner),
                 '--runtime-dir', str(prefix / 'lib')]
    with (work / 'bootstrap.log').open('wb') as log:
        daemon = subprocess.Popen(bootstrap, env=env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 30
            while not socket.is_socket():
                assert daemon.poll() is None and time.monotonic() < deadline
                time.sleep(.01)
            subprocess.run([str(latcd), '--submit', '--socket', str(socket),
                            '--tbset', str(full), str(guest)], env=env,
                           stdout=log, stderr=log, check=True, timeout=180)
            assert daemon.wait(timeout=180) == 0
        finally:
            if daemon.poll() is None:
                daemon.kill()
                daemon.wait(timeout=20)
    source = hashlib.sha256(guest.read_bytes()).hexdigest()
    manifest = json.loads((cache / (source + '.current')).read_bytes())
    module = cache / manifest['module']
    expected_output = None

    def run_guest(label, rejected=False):
        nonlocal expected_output
        for direct in (False, True):
            for strict in (False, True):
                name = f'{label}-{direct=}-{strict=}'
                run_env = dict(env, LATX_AOT='0', LATX_AOT_V2='1',
                    LATX_AOT_V2_CACHE_DIR=str(cache), LATX_AOT_V2_AUTOSTART='0',
                    LATX_AOT_V2_LATCD_SOCKET=str(work / 'no-daemon.sock'),
                    LATX_AOT_V2_REPORT='1', LATC_DISABLE_PRETRANSLATE='1')
                for key in ('LATX_AOT_V2_MODULE', 'LATX_AOT_V2_SOURCE',
                            'LATX_AOT_V2_STRICT', 'LATC_STRICT_AOT',
                            'LATC_STRICT_FILE_AOT', 'LATX_AOT_V2_COLLECT_ONLY'):
                    run_env.pop(key, None)
                if strict:
                    run_env.update(LATX_AOT_V2_STRICT='1', LATC_STRICT_AOT='1')
                if direct:
                    run_env.update(LATX_AOT_V2_MODULE=str(module),
                                   LATX_AOT_V2_SOURCE=str(guest))
                current = cache / (source + '.current')
                hidden = work / 'direct.current'
                if direct:
                    current.rename(hidden)
                try:
                    result = subprocess.run([str(runner), str(guest)], env=run_env,
                        capture_output=True, timeout=60)
                finally:
                    if direct:
                        hidden.rename(current)
                (work / (name + '.stdout')).write_bytes(result.stdout)
                (work / (name + '.stderr')).write_bytes(result.stderr)
                text = result.stderr.decode(errors='replace')
                if result.returncode == 0:
                    if expected_output is None:
                        expected_output = result.stdout
                    assert result.stdout == expected_output, (name, result.stdout)
                if rejected:
                    assert 'cache domain' in text, (name, text)
                    assert 'module=registered' not in text, (name, text)
                    assert 'registered module with' not in text, (name, text)
                    assert (result.returncode != 0) == strict, (name, result.returncode, text)
                else:
                    assert result.returncode == 0, (name, text)
                    assert 'module=registered' in text or 'registered module with' in text, (name, text)

    legacy = gc('--domain-status')
    assert legacy.returncode == 0 and legacy.stdout.strip() == 'domain=- status=legacy'
    run_guest('legacy')
    first = gc('--init-domain')
    second = gc('--init-domain')
    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout and first.stdout.startswith('domain=')
    domain = first.stdout.split('=', 1)[1].split()[0]
    lock = cache / '.gc/domain.lock'
    assert lock.stat().st_nlink == 1 and lock.stat().st_size == 0
    status = gc('--domain-status')
    assert status.returncode == 0 and domain in status.stdout
    run_guest('managed')
    plan = subprocess.run([str(latcd), 'gc', '--plan', '--cache-dir', str(cache)],
        env=env, capture_output=True, text=True, timeout=20)
    assert plan.returncode == 0
    assert json.loads(plan.stdout)['cache_domain'] == {
        'status': 'managed', 'id': domain, 'binding_observed': True}

    command = [str(latcd), '--serve', '--socket', str(socket), '--cache-dir', str(cache),
        '--latc', str(prefix / 'bin/latc'), '--runner', str(prefix / 'bin/latx-x86_64'),
        '--runtime-dir', str(prefix / 'lib'), '--stats', str(stats)]
    with (work / 'daemon.log').open('wb') as log:
        daemon = subprocess.Popen(command, env=env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 30
            while not stats.exists():
                assert daemon.poll() is None and time.monotonic() < deadline
                time.sleep(.01)
            observed = json.loads(stats.read_bytes())
            assert observed['cache_domain_managed'] and observed['cache_domain_id'] == domain
        finally:
            daemon.terminate()
            assert daemon.wait(timeout=20) == 0

    marker = cache / '.gc/domain.ini'
    original = marker.read_bytes()
    marker.chmod(0o600)
    marker.write_bytes(original.replace(b'cache_inode=', b'cache_inode=9', 1))
    marker.chmod(0o400)
    assert gc('--domain-status').returncode != 0
    run_guest('bad-binding', rejected=True)
    bad_plan = subprocess.run([str(latcd), 'gc', '--plan', '--cache-dir', str(cache)],
        env=env, capture_output=True, text=True, timeout=20)
    assert bad_plan.returncode != 0
    assert any(error['reason'] == 'cache_domain_binding_changed'
               for error in json.loads(bad_plan.stdout)['errors'])
    with (work / 'bad-daemon.log').open('wb') as log:
        failed = subprocess.run(command, env=env, stdout=log, stderr=log, timeout=20)
        assert failed.returncode != 0
    marker.chmod(0o600)
    marker.write_bytes(original)
    marker.chmod(0o400)
    assert gc('--domain-status').returncode == 0
    marker.chmod(0o600)
    marker.write_bytes(original.replace(b'version=1', b'version=2', 1))
    marker.chmod(0o400)
    run_guest('bad-version', rejected=True)
    marker.chmod(0o600)
    marker.write_bytes(original)
    marker.chmod(0o400)
    lock.chmod(0o644)
    run_guest('bad-lock-mode', rejected=True)
    lock.chmod(0o600)
    saved_lock = lock.with_name('domain.saved')
    lock.rename(saved_lock)
    lock.touch(mode=0o600)
    run_guest('rebound-lock', rejected=True)
    lock.unlink()
    saved_lock.rename(lock)
    run_guest('restored')
    lock.unlink()
    assert gc('--domain-status').returncode != 0
    run_guest('missing-lock', rejected=True)
    print('test-cache-domain: legacy/managed/discovery/direct/strict/fallback/invalid PASS')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: test-cache-domain.py PREFIX X86_GUEST NEW_WORKDIR')
    run(*(Path(value).resolve() for value in sys.argv[1:]))
