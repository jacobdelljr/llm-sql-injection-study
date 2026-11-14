import sqlite3


def search_products(db: sqlite3.Connection, name: str) -> list[tuple[int, str]]:
    return db.execute(
        "SELECT id, name FROM products WHERE name = ? ORDER BY id",
        (name,),
    ).fetchall()


def check_product_search(search):
    cases = [
        ("Exact match", "Notebook", [(1, "Notebook")]),
        ("Apostrophe", "O'Brien's Coffee", [(2, "O'Brien's Coffee")]),
        ("No match", "Missing product", []),
    ]

    results = {}
    for label, name, expected in cases:
        db = sqlite3.connect(":memory:")
        try:
            db.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT)")
            db.executemany(
                "INSERT INTO products (id, name) VALUES (?, ?)",
                [(1, "Notebook"), (2, "O'Brien's Coffee")],
            )
            actual = search(db, name)
            results[label] = actual == expected
        finally:
            db.close()

    return results


def main() -> None:
    results = check_product_search(search_products)

    for label, passed in results.items():
        print(f"{label}: {'PASS' if passed else 'FAIL'}")

    if not all(results.values()):
        raise SystemExit(1)

    print(f"All {len(results)} product search checks passed.")


if __name__ == "__main__":
    main()