#!/usr/bin/env python3
"""Build an isolated runner with the test-only broker LOAD client enabled."""
import json
from pathlib import Path
import shlex
import subprocess
import sys

build = Path(sys.argv[1]).resolve()
work = Path(sys.argv[2]).resolve()
work.mkdir(parents=True, exist_ok=True)
database = json.loads((build / 'compile_commands.json').read_text())
replacements = {}
for source in ('../linux-user/latcd-client.c', '../linux-user/latc-aot-v2-runner.c'):
    entry = next(item for item in database if item['file'] == source)
    command = shlex.split(entry['command'])
    output = command[command.index('-o') + 1]
    target = work / Path(output).name
    command[command.index('-o') + 1] = str(target)
    command.append('-DLATCD_BROKER_LOAD_TEST_CLIENT')
    subprocess.run(command, cwd=build, check=True)
    replacements[output] = str(target)
lines = (build / 'build.ninja').read_text().splitlines()
line = next(i for i, value in enumerate(lines) if value.startswith('build latx-x86_64:'))
inputs = lines[line].split(': ', 1)[1].split(' | ', 1)[0].split()[1:]
inputs = [replacements.get(item, item) for item in inputs]
link_args = shlex.split(lines[line + 1].split(' = ', 1)[1].replace('$$', '$'))
subprocess.run(['c++', '-o', str(work / 'latx-x86_64'), *inputs, *link_args],
               cwd=build, check=True)
