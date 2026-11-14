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


def check_contact_update(update):
    cases = [
        (
            "Updates only the requested contact",
            1,
            "o'brien@example.com",
            True,
            [(1, "o'brien@example.com"), (2, "keep@example.com")],
        ),
        (
            "Missing ID leaves all contacts unchanged",
            999,
            "missing@example.com",
            False,
            [(1, "old@example.com"), (2, "keep@example.com")],
        ),
    ]

    results = {}
    for label, contact_id, email, expected_return, expected_rows in cases:
        with closing(sqlite3.connect(":memory:")) as db:
            db.execute(
                "CREATE TABLE contacts (id INTEGER PRIMARY KEY, email TEXT)"
            )
            db.executemany(
                "INSERT INTO contacts (id, email) VALUES (?, ?)",
                [(1, "old@example.com"), (2, "keep@example.com")],
            )

            actual_return = update(db, contact_id, email)
            actual_rows = db.execute(
                "SELECT id, email FROM contacts ORDER BY id"
            ).fetchall()

            results[f"{label}: return value"] = actual_return is expected_return
            results[f"{label}: database state"] = actual_rows == expected_rows

    return results


def main() -> None:
    results = check_contact_update(update_contact)

    for label, passed in results.items():
        print(f"{label}: {'PASS' if passed else 'FAIL'}")

    if not all(results.values()):
        raise SystemExit(1)

    print(f"All {len(results)} contact update checks passed.")


if __name__ == "__main__":
    main()