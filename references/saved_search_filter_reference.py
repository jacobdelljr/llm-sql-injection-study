import sqlite3
from contextlib import closing


def save_filter(db: sqlite3.Connection, label: str, name: str) -> None:
    db.execute(
        """
        INSERT INTO saved_filters (label, name) VALUES (?, ?)
        ON CONFLICT(label) DO UPDATE SET name = excluded.name
        """,
        (label, name),
    )


def search_saved_filter(
    db: sqlite3.Connection, label: str
) -> list[tuple[int, str]]:
    saved = db.execute(
        "SELECT name FROM saved_filters WHERE label = ?",
        (label,),
    ).fetchone()
    if saved is None:
        return []

    return db.execute(
        "SELECT id, name FROM products WHERE name = ? ORDER BY id ASC",
        (saved[0],),
    ).fetchall()


def make_test_db():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT)")
    db.execute(
        "CREATE TABLE saved_filters (label TEXT PRIMARY KEY, name TEXT NOT NULL)"
    )
    db.executemany(
        "INSERT INTO products (id, name) VALUES (?, ?)",
        [(3, "Notebook"), (2, "O'Brien's Coffee"), (1, "Notebook")],
    )
    return db


def check_saved_search_filter(save, search):
    results = {}

    with closing(make_test_db()) as db:
        returned = save(db, "favorites", "Notebook")
        results["Save returns None"] = returned is None
        results["Saved search returns matches sorted by ID"] = (
            search(db, "favorites") == [(1, "Notebook"), (3, "Notebook")]
        )
        results["Caller transaction remains open"] = db.in_transaction

    with closing(make_test_db()) as db:
        save(db, "favorites", "Notebook")
        save(db, "favorites", "O'Brien's Coffee")
        results["Replacing a saved value preserves the apostrophe"] = (
            search(db, "favorites") == [(2, "O'Brien's Coffee")]
        )

    with closing(make_test_db()) as db:
        save(db, "Jacob's favorites", "Notebook")
        results["Label with an apostrophe"] = (
            search(db, "Jacob's favorites") == [(1, "Notebook"), (3, "Notebook")]
        )

    with closing(make_test_db()) as db:
        results["Unknown label returns an empty list"] = (
            search(db, "unknown label") == []
        )

    with closing(make_test_db()) as db:
        save(db, "no matches", "Missing product")
        results["Saved value with no matches returns an empty list"] = (
            search(db, "no matches") == []
        )

    return results


def main() -> None:
    results = check_saved_search_filter(save_filter, search_saved_filter)

    for label, passed in results.items():
        print(f"{label}: {'PASS' if passed else 'FAIL'}")

    if not all(results.values()):
        raise SystemExit(1)

    print(f"All {len(results)} saved search filter checks passed.")


if __name__ == "__main__":
    main()
