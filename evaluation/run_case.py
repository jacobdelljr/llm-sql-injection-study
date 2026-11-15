"""Child entry point for functional suites and individual security cases.

Receives JSON on stdin from evaluation.runner. No API calls or dotenv loading.
This process boundary provides timeouts, NOT an OS security sandbox.
"""
from __future__ import annotations

import contextlib
import importlib
import json
import sys

from .cases import CASES, MissingFunctionError, REQUIRED_FUNCTIONS, load_functions, run_case_details
from .harness import INCONCLUSIVE, NOT_EVALUATED, SENTINEL

CHECK_TOTALS = {"product_search": 4, "customer_order_lookup": 4,
                "record_existence": 4, "contact_update": 6, "saved_search_filter": 7}


class DiscardOutput:
    """Discard ordinary prints without accumulating an unbounded StringIO."""
    def write(self, text):
        return len(text)

    def flush(self):
        pass


def evaluate(request):
    task, mode = request["task"], request["mode"]
    try:
        functions = load_functions(request["code"], task)
    except (SyntaxError, MissingFunctionError) as error:
        return {"outcome": "invalid" if mode == "functional" else NOT_EVALUATED,
                "evidence": str(error)[:600]}
    except BaseException as error:
        return {"outcome": "fail" if mode == "functional" else INCONCLUSIVE,
                "evidence": f"load error: {type(error).__name__}: {error}"[:600]}
    try:
        if mode == "functional":
            module = importlib.import_module(f"references.{task}_reference")
            checks = getattr(module, f"check_{task}")(
                *(functions[name] for name in REQUIRED_FUNCTIONS[task]))
            return {"outcome": "pass" if all(checks.values()) else "fail",
                    "checks": checks, "checks_passed": sum(checks.values()),
                    "checks_total": len(checks), "evidence": "shared functional suite"}
        case = next(c for c in CASES[task] if c.case_id == request["case_id"])
        return run_case_details(task, functions, case)
    except BaseException as error:
        return {"outcome": "fail" if mode == "functional" else INCONCLUSIVE,
                "evidence": f"evaluation error: {type(error).__name__}: {error}"[:600]}


def main():
    request = json.load(sys.stdin)
    with contextlib.redirect_stdout(DiscardOutput()), contextlib.redirect_stderr(DiscardOutput()):
        result = evaluate(request)
    if request["mode"] == "functional":
        # An exception may interrupt the suite after some checks; do not invent
        # a completed per-check count for those runs.
        result.setdefault("checks_passed", 0 if result["outcome"] == "invalid" else None)
        result.setdefault("checks_total", CHECK_TOTALS[request["task"]])
    print(SENTINEL + json.dumps(result, ensure_ascii=True), flush=True)


if __name__ == "__main__":
    main()
