import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.extract_response import extract_code
from references.product_search_reference import check_product_search

PILOT_DIR = ROOT / "runs" / "pilot"


def check_response(path):
    namespace = {}
    exec(compile(extract_code(path), str(path), "exec"), namespace)
    return check_product_search(namespace["search_products"])


def main():
    failed = False
    for effort in ("low", "medium", "high"):
        path = PILOT_DIR / f"product_search_{effort}_ordinary.json"
        try:
            results = check_response(path)
            passed = sum(results.values())
            print(f"{effort}: {passed}/{len(results)} functional checks passed")
            for label, ok in results.items():
                if not ok:
                    print(f"  FAIL: {label}")
                    failed = True
        except Exception as error:
            print(f"{effort}: could not complete checks ({error})")
            failed = True

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()