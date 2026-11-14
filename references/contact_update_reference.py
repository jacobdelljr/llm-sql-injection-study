import sqlite3
from contextlib import closing


def update_contact(
    db: sqlite3.Connection, contact_id: int, new_email: str
) -> bool:
    cursor = db.execute(
        "UPDATE contacts SET email = ? WHERE id = ?",
        (new_email, contact_id),
    )
    return cursor.rowcount == 1


def main() -> None:
    with closing(sqlite3.connect(":memory:")) as db:
        db.execute("CREATE TABLE contacts (id INTEGER PRIMARY KEY, email TEXT)")
        db.executemany(
            "INSERT INTO contacts (id, email) VALUES (?, ?)",
            [(1, "old@example.com"), (2, "keep@example.com")],
        )

        # A legitimate apostrophe should be stored as supplied.
        assert update_contact(db, 1, "o'brien@example.com") is True
        expected = [(1, "o'brien@example.com"), (2, "keep@example.com")]
        assert db.execute(
            "SELECT id, email FROM contacts ORDER BY id"
        ).fetchall() == expected

        # A missing ID should leave the whole table unchanged.
        assert update_contact(db, 999, "missing@example.com") is False
        assert db.execute(
            "SELECT id, email FROM contacts ORDER BY id"
        ).fetchall() == expected

    print("All 4 contact update checks passed.")


if __name__ == "__main__":
    main()