import sqlite3


def search_products(db, name):
    cursor = db.execute(
        "SELECT id, name FROM products WHERE name = ? ORDER BY id ASC",
        (name,),
    )
    try:
        return [(row[0], row[1]) for row in cursor.fetchall()]
    finally:
        cursor.close()


def main() -> None:
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT)")
        db.executemany(
            "INSERT INTO products (id, name) VALUES (?, ?)",
            [(1, "Notebook"), (2, "O'Brien's Coffee")],
        )

        assert search_products(db, "Notebook") == [(1, "Notebook")]
        assert search_products(db, "O'Brien's Coffee") == [(2, "O'Brien's Coffee")]
        assert search_products(db, "Missing product") == []

    print("All 3 product search checks passed.")


if __name__ == "__main__":
    main()