"""Check safe references and known-behavior controls through real worker processes."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from evaluation.cases import CASES, fingerprint
from evaluation.controls import CONTROLS
from evaluation.runner import evaluator_hash, run_worker, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=5)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("output already exists; choose a new path to preserve validation evidence")
    if args.timeout <= 0:
        parser.error("timeout must be positive")
    records = []
    for task in CASES:
        source = (ROOT / "references" / f"{task}_reference.py").read_text(encoding="utf-8")
        result = run_worker(source, task, timeout=args.timeout)
        records.append({"control": "reference", "task": task, "case_id": "functional",
                        "expected": ["pass"], "matched": result["outcome"] == "pass", **result})
        for case in CASES[task]:
            result = run_worker(source, task, case_id=case.case_id, timeout=args.timeout)
            records.append({"control": "reference", "task": task, "case_id": case.case_id,
                            "expected": ["pass"], "matched": result["outcome"] == "pass", **result})
    for control in CONTROLS:
        for case in CASES[control.task]:
            result = run_worker(control.source, control.task, case_id=case.case_id, timeout=args.timeout)
            expected = control.acceptable(case.case_id)
            records.append({"control": control.name, "kind": control.kind, "task": control.task,
                            "case_id": case.case_id, "expected": expected,
                            "matched": result["outcome"] in expected, **result})
    failed = [r for r in records if not r["matched"]]
    report = {"created_utc": datetime.now(timezone.utc).isoformat(), "python": sys.version,
              "sqlite": sqlite3.sqlite_version, "case_fingerprint": fingerprint(),
              "evaluator_sha256": evaluator_hash(), "timeout_seconds": args.timeout,
              "checks": len(records), "mismatches": len(failed),
              "outcomes": dict(Counter(r["outcome"] for r in records)), "results": records}
    write_json(args.out, report)
    print(f"{len(records) - len(failed)}/{len(records)} expected outcomes matched; saved {args.out}")
    for result in failed:
        print(result["control"], result["case_id"], result["outcome"], result["evidence"])
    return bool(failed)


if __name__ == "__main__":
    raise SystemExit(main())
