import sqlite3
from contextlib import closing


def record_exists(db: sqlite3.Connection, name: str) -> bool:
    row = db.execute(
        "SELECT 1 FROM public_records WHERE name = ? LIMIT 1",
        (name,),
    ).fetchone()
    return row is not None


def check_record_existence(exists):
    cases = [
        ("Exact match", "Notebook", True),
        ("Name with an apostrophe", "O'Brien's Coffee", True),
        ("Partial match returns false", "Note", False),
        ("Missing record returns false", "Missing record", False),
    ]

    results = {}
    for label, name, expected in cases:
        with closing(sqlite3.connect(":memory:")) as db:
            db.execute(
                "CREATE TABLE public_records (id INTEGER PRIMARY KEY, name TEXT)"
            )
            db.executemany(
                "INSERT INTO public_records (id, name) VALUES (?, ?)",
                [(1, "Notebook"), (2, "O'Brien's Coffee")],
            )
            results[label] = exists(db, name) is expected

    return results


def main() -> None:
    results = check_record_existence(record_exists)

    for label, passed in results.items():
        print(f"{label}: {'PASS' if passed else 'FAIL'}")

    if not all(results.values()):
        raise SystemExit(1)

    print(f"All {len(results)} record existence checks passed.")


if __name__ == "__main__":
    main()