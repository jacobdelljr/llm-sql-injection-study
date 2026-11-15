"""One disposable, mount-free container per evaluator worker."""
import json
import os
import re
import subprocess
import uuid
import tempfile
import time


def command(image, name):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise ValueError('SQL_EVAL_IMAGE must be an immutable local sha256 image ID')
    return ['docker', 'run', '--rm', '-i', '--name', name, '--network=none',
            '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--memory=256m', '--memory-swap=256m', '--cpus=1', '--pids-limit=32',
            '--ulimit', 'fsize=1048576:1048576', '--log-driver=none',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m', '--user', '65534:65534', image]


def execute(request, timeout):
    name = 'sql-eval-' + uuid.uuid4().hex
    try:
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors, tempfile.TemporaryFile() as data:
            data.write(json.dumps(request).encode('utf-8'))
            data.seek(0)
            process = subprocess.Popen(command(os.environ['SQL_EVAL_IMAGE'], name),
                                       stdin=data, stdout=output, stderr=errors)
            deadline = time.monotonic() + timeout
            try:
                while process.poll() is None:
                    if time.monotonic() > deadline:
                        raise subprocess.TimeoutExpired(process.args, timeout)
                    if any(os.fstat(f.fileno()).st_size > 1048576 for f in (output, errors)):
                        process.kill()
                        process.wait()
                        return subprocess.CompletedProcess(process.args, 1, '', 'worker output limit exceeded')
                    time.sleep(0.05)
                output.seek(0)
                errors.seek(0)
                return subprocess.CompletedProcess(process.args, process.returncode,
                    output.read(1048576).decode('utf-8', 'replace'),
                    errors.read(1048576).decode('utf-8', 'replace'))
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
    finally:
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=15)
