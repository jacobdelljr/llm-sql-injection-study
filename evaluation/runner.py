"""Timeout and bookkeeping utilities. Local worker execution is not a sandbox."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from .harness import SENTINEL

ROOT = Path(__file__).resolve().parent.parent


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def evaluator_hash():
    """Include verdict logic, fixtures, references, extraction and orchestration."""
    paths = sorted([*ROOT.glob("evaluation/*.py"), *ROOT.glob("references/*.py"),
                    ROOT / "scripts/extract_response.py", ROOT / "scripts/run_evaluation.py",
                    ROOT / "scripts/validate_security.py"])
    return sha256(os.environ.get("SQL_EVAL_IMAGE", "local").encode() + b"\0" + b"".join(p.relative_to(ROOT).as_posix().encode() + b"\0" + p.read_bytes()
                          for p in paths))


def run_worker(code, task, *, case_id=None, timeout=5.0):
    mode = "security" if case_id is not None else "functional"
    request = {"code": code, "task": task, "mode": mode, "case_id": case_id}
    # -I ignores user site packages and PYTHON* settings; -S skips site startup.
    # No .env loading, credentials, shell, or inherited API keys.
    bootstrap = ("import runpy,sys; sys.path.insert(0, " + repr(str(ROOT)) + "); "
                 "runpy.run_module('evaluation.run_case', run_name='__main__')")
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {"SYSTEMROOT", "WINDIR"}}
    fallback = "inconclusive" if mode == "security" else "fail"
    with tempfile.TemporaryDirectory(prefix="sql-eval-") as work:
        env.update(TEMP=work, TMP=work)
        try:
            process = ( __import__("evaluation.docker_backend", fromlist=["execute"]).execute(request, timeout)
                        if os.environ.get("SQL_EVAL_IMAGE") else subprocess.run([sys.executable, "-I", "-S", "-B", "-c", bootstrap],
                                     input=json.dumps(request), text=True, encoding="utf-8",
                                     errors="replace", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     cwd=work, env=env, timeout=timeout))
        except subprocess.TimeoutExpired:
            return {"outcome": fallback, "evidence": f"worker timed out after {timeout:g}s"}
    lines = [line[len(SENTINEL):] for line in process.stdout.splitlines() if line.startswith(SENTINEL)]
    if process.returncode != 0 or len(lines) != 1:
        return {"outcome": fallback, "evidence": f"worker failed (exit={process.returncode}, "
                f"result_lines={len(lines)})"}
    try:
        result = json.loads(lines[0])
        allowed = {"pass", "fail", "invalid"} if mode == "functional" else {
            "pass", "violation", "inconclusive", "not_evaluated"}
        if not isinstance(result, dict) or result.get("outcome") not in allowed:
            raise ValueError("invalid worker result")
        return result
    except (ValueError, TypeError):
        return {"outcome": fallback, "evidence": "invalid worker JSON"}


def write_json(path, data):
    """Atomic checkpoint replacement. The caller owns this result directory."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    temporary.replace(path)
