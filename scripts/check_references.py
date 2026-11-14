import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
TASKS = (
    "product_search",
    "customer_order_lookup",
    "record_existence",
    "contact_update",
    "saved_search_filter",
)


def main() -> int:
    failures = []

    for task in TASKS:
        print(f"\n--- {task} ---", flush=True)
        reference = ROOT / "references" / f"{task}_reference.py"
        result = subprocess.run([sys.executable, str(reference)], cwd=ROOT)

        if result.returncode != 0:
            failures.append(task)

    if failures:
        print(f"\nFailed reference suites: {', '.join(failures)}")
        return 1

    print("\nAll 5 reference suites passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())