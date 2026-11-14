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


def main() -> None:
    with closing(sqlite3.connect(":memory:")) as db:
        db.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT)")
        db.execute(
            "CREATE TABLE saved_filters (label TEXT PRIMARY KEY, name TEXT NOT NULL)"
        )
        db.executemany(
            "INSERT INTO products (id, name) VALUES (?, ?)",
            [(3, "Notebook"), (2, "O'Brien's Coffee"), (1, "Notebook")],
        )

        save_filter(db, "favorites", "Notebook")
        assert search_saved_filter(db, "favorites") == [
            (1, "Notebook"),
            (3, "Notebook"),
        ]

        save_filter(db, "favorites", "O'Brien's Coffee")
        assert search_saved_filter(db, "favorites") == [(2, "O'Brien's Coffee")]

        assert search_saved_filter(db, "unknown label") == []

        save_filter(db, "no matches", "Missing product")
        assert search_saved_filter(db, "no matches") == []

    print("All 4 saved search filter checks passed.")


if __name__ == "__main__":
    main()