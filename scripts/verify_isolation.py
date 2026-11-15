"""Verify the chosen Docker image and restrictions without API calls."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluation.docker_backend import command
from evaluation.runner import sha256, write_json


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    if args.out.exists():
        p.error('choose a new report path')
    image = os.environ.get('SQL_EVAL_IMAGE', '')
    paths = [*ROOT.glob('evaluation/*.py'), *ROOT.glob('references/*.py'),
             *[ROOT / 'scripts' / n for n in ('extract_response.py', 'run_evaluation.py', 'validate_security.py')]]
    expected = {p.relative_to(ROOT).as_posix(): sha256(p.read_bytes()) for p in paths}
    source = '''
import os, json, pathlib, hashlib, sqlite3, sys
assert os.getuid() == 65534
assert len(pathlib.Path('/proc/net/route').read_text().strip().splitlines()) == 1
assert int(pathlib.Path('/sys/fs/cgroup/memory.max').read_text()) <= 268435456
assert int(pathlib.Path('/sys/fs/cgroup/pids.max').read_text()) <= 32
assert 'ANTHROPIC_API_KEY' not in os.environ
try:
    pathlib.Path('/app/write-check').write_text('test')
except OSError:
    pass
else:
    raise AssertionError('application filesystem is writable')
paths = json.loads(sys.stdin.read())
print(json.dumps({'files': {p: hashlib.sha256(pathlib.Path('/app', p).read_bytes()).hexdigest() for p in paths},
                  'python': sys.version, 'sqlite': sqlite3.sqlite_version}))
'''
    name = 'sql-verify-' + uuid.uuid4().hex
    try:
        result = subprocess.run(command(image, name) + ['python', '-c', source],
                                input=json.dumps(list(expected)), text=True, capture_output=True, timeout=30)
        if result.returncode:
            raise SystemExit('Isolation verification failed: ' + result.stderr[-2000:])
        observed = json.loads(result.stdout)
        if observed['files'] != expected:
            raise SystemExit('Container source differs from working tree. Rebuild before freezing.')
        write_json(args.out, {'image': image, 'verified': True, **observed})
        print('Verified image source, non-root user, read-only application, no routes, memory/PID limits and no API key.')
    finally:
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=15)


if __name__ == '__main__':
    main()
