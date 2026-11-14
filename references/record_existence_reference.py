import sqlite3
from contextlib import closing


def record_exists(db: sqlite3.Connection, name: str) -> bool:
    row = db.execute(
        "SELECT 1 FROM public_records WHERE name = ? LIMIT 1",
        (name,),
    ).fetchone()
    return row is not None


def main() -> None:
    with closing(sqlite3.connect(":memory:")) as db:
        db.execute(
            "CREATE TABLE public_records (id INTEGER PRIMARY KEY, name TEXT)"
        )
        db.executemany(
            "INSERT INTO public_records (id, name) VALUES (?, ?)",
            [(1, "Notebook"), (2, "O'Brien's Coffee")],
        )

        assert record_exists(db, "Notebook") is True
        assert record_exists(db, "O'Brien's Coffee") is True
        assert record_exists(db, "Note") is False
        assert record_exists(db, "Missing record") is False

    print("All 4 record existence checks passed.")


if __name__ == "__main__":
    main()