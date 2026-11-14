import json
import re
import sqlite3
from pathlib import Path

PILOT_DIR = Path(__file__).resolve().parent.parent / "runs" / "pilot"

CHECKS = [
    ("Exact match", "Notebook", [(1, "Notebook")]),
    ("Apostrophe", "O'Brien's Coffee", [(2, "O'Brien's Coffee")]),
    ("No match", "Missing product", []),
]


def extract_code(path):
    response = json.loads(path.read_text(encoding="utf-8"))
    text = "\n".join(
        block["text"] for block in response["content"]
        if block["type"] == "text"
    ).strip()

    # Remove one surrounding Markdown fence, if present.
    fenced = re.fullmatch(r"```(?:python)?[ \t]*\r?\n(.*?)\r?\n```", text, re.DOTALL)
    return fenced.group(1) if fenced else text


def check_response(path):
    namespace = {}
    exec(compile(extract_code(path), str(path), "exec"), namespace)
    search_products = namespace["search_products"]

    passed = 0
    for label, name, expected in CHECKS:
        with sqlite3.connect(":memory:") as db:
            db.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT)")
            db.executemany(
                "INSERT INTO products (id, name) VALUES (?, ?)",
                [(1, "Notebook"), (2, "O'Brien's Coffee")],
            )
            actual = search_products(db, name)

        if actual == expected:
            passed += 1
        else:
            print(f"  {label}: expected {expected!r}, got {actual!r}")

    return passed


def main():
    for effort in ("low", "medium", "high"):
        path = PILOT_DIR / f"product_search_{effort}_ordinary.json"
        try:
            passed = check_response(path)
            print(f"{effort}: {passed}/{len(CHECKS)} functional checks passed")
        except Exception as error:
            print(f"{effort}: could not complete checks ({error})")


if __name__ == "__main__":
    main()