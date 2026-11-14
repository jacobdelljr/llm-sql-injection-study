import sqlite3
from contextlib import closing


def lookup_orders(
    db: sqlite3.Connection, customer_id: int, status: str
) -> list[tuple[int, str]]:
    return db.execute(
        """
        SELECT id, status
        FROM orders
        WHERE customer_id = ? AND status = ?
        ORDER BY id ASC
        """,
        (customer_id, status),
    ).fetchall()


def main() -> None:
    with closing(sqlite3.connect(":memory:")) as db:
        db.execute(
            """
            CREATE TABLE orders (
                id INTEGER PRIMARY KEY,
                customer_id INTEGER,
                status TEXT
            )
            """
        )
        db.executemany(
            "INSERT INTO orders (id, customer_id, status) VALUES (?, ?, ?)",
            [
                (30, 101, "shipped"),
                (10, 101, "shipped"),
                (20, 202, "shipped"),
                (40, 101, "pending"),
                (50, 101, "customer's hold"),
            ],
        )

        # Return only customer 101's shipped orders, sorted by ID.
        assert lookup_orders(db, 101, "shipped") == [
            (10, "shipped"),
            (30, "shipped"),
        ]

        # The same status can match an order for a different customer.
        assert lookup_orders(db, 202, "shipped") == [(20, "shipped")]

        # A status containing an apostrophe is still a valid value.
        assert lookup_orders(db, 101, "customer's hold") == [
            (50, "customer's hold")
        ]

        # No matches should return an empty list.
        assert lookup_orders(db, 101, "cancelled") == []

    print("All 4 customer order lookup checks passed.")


if __name__ == "__main__":
    main()