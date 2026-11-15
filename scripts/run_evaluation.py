"""Evaluate saved responses offline; never generate, repair, or replace a response."""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from evaluation.cases import CASES, fingerprint
from evaluation.controls import CONTROLS
from evaluation.run_case import CHECK_TOTALS
from evaluation.runner import evaluator_hash, run_worker, sha256, write_json
from scripts.extract_response import extract_code


def read_jobs(pilot, schedule):
    if pilot:
        return [{"run_id": f"product_search_{effort}_ordinary", "task": "product_search",
                 "effort": effort, "condition": "ordinary", "repetition": None}
                for effort in ("low", "medium", "high")]
    data = json.loads(schedule.read_text(encoding="utf-8-sig"))
    jobs = data["runs"]
    expected = {(task, effort, condition, repetition)
                for task in CASES for effort in ("low", "medium", "high")
                for condition in ("ordinary", "general", "specific") for repetition in range(1, 6)}
    actual = {(j["task"], j["effort"], j["condition"], j["repetition"]) for j in jobs}
    if len(jobs) != 225 or actual != expected or len({j["run_id"] for j in jobs}) != 225:
        raise ValueError("main schedule must contain the complete unique 5 x 3 x 3 x 5 design")
    for job in jobs:
        canonical = f"{job['task']}_{job['effort']}_{job['condition']}_r{job['repetition']:02d}"
        if job["run_id"] != canonical or not re.fullmatch(r"[a-z0-9_]+", job["run_id"]):
            raise ValueError("noncanonical run_id in schedule")
    return jobs


def evaluate_response(job, path, out, timeout):
    task, run_id = job["task"], job["run_id"]
    result = {"run_id": run_id, "task": task, "security": [], "metadata": {}}
    unavailable = None
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(raw, dict):
            raise ValueError("response JSON must be an object")
        result["metadata"] = {key: raw.get(key) for key in ("id", "model", "stop_reason", "usage")}
        if raw.get("stop_reason") != "end_turn":
            raise ValueError(f"incomplete or unsupported completion: {raw.get('stop_reason')!r}")
        code = extract_code(path)
        compile(code, str(path), "exec")
    except FileNotFoundError:
        unavailable = "response file missing"
        outcome = "not_evaluated"
    except (ValueError, KeyError, TypeError, SyntaxError, UnicodeError) as error:
        unavailable = f"{type(error).__name__}: {error}"[:600]
        outcome = "invalid"
    if unavailable is not None:
        result["functional"] = {"outcome": outcome, "evidence": unavailable,
                                "checks_passed": 0, "checks_total": CHECK_TOTALS[task]}
    else:
        extracted = out / "extracted" / f"{run_id}.py"
        extracted.parent.mkdir(parents=True, exist_ok=True)
        if extracted.exists() and extracted.read_text(encoding="utf-8") != code:
            raise ValueError(f"extracted code changed: {run_id}")
        extracted.write_text(code, encoding="utf-8")
        result["code_sha256"] = sha256(code.encode("utf-8"))
        result["functional"] = run_worker(code, task, timeout=timeout)
        result["functional"].setdefault("checks_passed", None)
        result["functional"].setdefault("checks_total", CHECK_TOTALS[task])
        if result["functional"]["outcome"] == "invalid":
            unavailable = result["functional"]["evidence"]
    # Functional failures remain in the denominator. Still evaluate runnable
    # failures: a functional bug must not conceal an observable attack result.
    for case in CASES[task]:
        observation = ({"outcome": "not_evaluated", "evidence": unavailable}
                       if unavailable else run_worker(code, task, case_id=case.case_id, timeout=timeout))
        result["security"].append({"case_id": case.case_id, **observation})
    result["combined_pass"] = result["functional"]["outcome"] == "pass" and all(
        case["outcome"] == "pass" for case in result["security"])
    return result


def write_csv(path, fields, rows):
    temporary = path.with_suffix(".csv.tmp")
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def summarize(jobs, results):
    by_id = {result["run_id"]: result for result in results}
    groups = {}
    for job in jobs:
        key = (job["effort"], job["condition"])
        group = groups.setdefault(key, {"effort": key[0], "condition": key[1],
                                       "scheduled": 0, "functional_pass": 0, "combined_pass": 0,
                                       "programs_with_observed_violation": 0})
        result = by_id[job["run_id"]]
        group["scheduled"] += 1
        group["functional_pass"] += result["functional"]["outcome"] == "pass"
        group["combined_pass"] += result["combined_pass"]
        group["programs_with_observed_violation"] += any(c["outcome"] == "violation" for c in result["security"])
    for group in groups.values():
        group["combined_percent"] = 100 * group["combined_pass"] / group["scheduled"]
        members = [by_id[j['run_id']] for j in jobs if
                   (j['effort'], j['condition']) == (group['effort'], group['condition'])]
        for field in ('input_tokens', 'output_tokens'):
            values = [(r.get('metadata', {}).get('usage') or {}).get(field) for r in members]
            values = [v for v in values if isinstance(v, int) and not isinstance(v, bool)]
            group[field + '_observations'] = len(values)
            group[field + '_mean'] = sum(values) / len(values) if values else None
    by_task = []
    for task in dict.fromkeys(j["task"] for j in jobs):
        subset = [r for r in results if r["task"] == task]
        by_task.append({"task": task, "scheduled": len(subset),
                        "functional_outcomes": dict(Counter(r["functional"]["outcome"] for r in subset)),
                        "security_case_outcomes": dict(Counter(c["outcome"] for r in subset for c in r["security"])),
                        "combined_pass": sum(r["combined_pass"] for r in subset)})
    return {"scheduled": len(jobs), "combined_pass": sum(r["combined_pass"] for r in results),
            "functional_outcomes": dict(Counter(r["functional"]["outcome"] for r in results)),
            "security_case_outcomes": dict(Counter(c["outcome"] for r in results for c in r["security"])),
            "by_condition": list(groups.values()), "by_task": by_task,
            "interpretation": "Observed violations require source/evidence review before reporting confirmed SQL injection. "
                              "A pass covers only the selected cases, not general security."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pilot", action="store_true", help="the three saved product-search responses")
    source.add_argument("--schedule", type=Path, help="complete main schedule.json")
    parser.add_argument("--responses", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="separate evaluation output directory")
    parser.add_argument("--controls-report", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--reviewed-local", action="store_true",
                        help="pilot only: source reviewed for execution with local user permissions")
    parser.add_argument("--isolated-environment", action="store_true",
                        help="operator attests this process is already inside a configured disposable VM/container")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("timeout must be positive")
    if not os.environ.get("SQL_EVAL_IMAGE") and not args.isolated_environment and not (args.pilot and args.reviewed_local):
        parser.error("use --reviewed-local for inspected pilot code, or run inside an isolated environment; "
                     "--isolated-environment does not create a sandbox")
    try:
        jobs = read_jobs(args.pilot, args.schedule)
        validation = json.loads(args.controls_report.read_text(encoding="utf-8"))
        version = evaluator_hash()
        expected_checks = len(CASES) + sum(map(len, CASES.values())) + sum(
            len(CASES[c.task]) for c in CONTROLS)
        if (validation.get("mismatches") != 0 or validation.get("checks") != expected_checks
                or validation.get("evaluator_sha256") != version
                or validation.get("python") != sys.version
                or validation.get("sqlite") != sqlite3.sqlite_version
                or validation.get("timeout_seconds") != args.timeout):
            raise ValueError("controls report does not validate this evaluator, runtime and timeout; rerun controls")
        args.out.mkdir(parents=True, exist_ok=True)
        manifest_path = args.out / "manifest.json"
        manifest = {"kind": "pilot" if args.pilot else "main", "jobs": jobs,
                    "evaluator_sha256": version, "case_fingerprint": fingerprint(),
                    "python": sys.version, "sqlite": sqlite3.sqlite_version,
                    "timeout_seconds": args.timeout,
                    "execution_mode": os.environ.get("SQL_EVAL_IMAGE") or ("isolated_environment_attested" if args.isolated_environment else "reviewed_local"),
                    "controls_report_sha256": sha256(args.controls_report.read_bytes()),
                    "responses": {j["run_id"]: sha256((args.responses / (j["run_id"] + ".json")).read_bytes())
                                  if (args.responses / (j["run_id"] + ".json")).is_file() else None for j in jobs},
                    "cases": {task: [asdict(c) for c in cases] for task, cases in CASES.items()}}
        # Dataclasses contain tuples; disk JSON contains lists. Compare the
        # serialized representation so an unchanged run can actually resume.
        manifest = json.loads(json.dumps(manifest))
        if manifest_path.exists():
            old = json.loads(manifest_path.read_text(encoding="utf-8"))
            old.pop("created_utc", None)
            if old != manifest:
                raise ValueError("inputs, evaluator, runtime or settings changed; use a new output directory")
        else:
            if any(args.out.iterdir()):
                raise ValueError("new output directory must be empty")
            write_json(manifest_path, {"created_utc": datetime.now(timezone.utc).isoformat(), **manifest})
        results = []
        for job in jobs:
            checkpoint = args.out / "details" / f"{job['run_id']}.json"
            if checkpoint.exists():
                result = json.loads(checkpoint.read_text(encoding="utf-8"))
                action = "resumed"
            else:
                result = evaluate_response(job, args.responses / f"{job['run_id']}.json", args.out, args.timeout)
                write_json(checkpoint, result)
                action = "evaluated"
            results.append(result)
            print(f"{action} {job['run_id']}: functional={result['functional']['outcome']}, "
                  f"combined_pass={result['combined_pass']}", flush=True)
        write_csv(args.out / "functional_results.csv", ["run_id", "outcome", "checks_passed", "checks_total"],
                  [{"run_id": r["run_id"], **r["functional"]} for r in results])
        write_csv(args.out / "security_results.csv", ["run_id", "case_id", "outcome", "evidence"],
                  [{"run_id": r["run_id"], **case} for r in results for case in r["security"]])
        summary = summarize(jobs, results)
        write_json(args.out / "summary.json", summary)
        print(f"Combined pass: {summary['combined_pass']}/{summary['scheduled']}; API calls: 0")
        return 0  # A completed measurement may legitimately contain failed programs.
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"Evaluation stopped: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
