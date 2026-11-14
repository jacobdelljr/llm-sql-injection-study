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


def check_customer_order_lookup(lookup):
    cases = [
        ("Customer and status filters, sorted by ID", 101, "shipped",
         [(10, "shipped"), (30, "shipped")]),
        ("Different customer, same status", 202, "shipped",
         [(20, "shipped")]),
        ("Status with an apostrophe", 101, "customer's hold",
         [(50, "customer's hold")]),
        ("No matching orders", 101, "cancelled", []),
    ]

    results = {}
    for label, customer_id, status, expected in cases:
        with closing(sqlite3.connect(":memory:")) as db:
            db.execute(
                "CREATE TABLE orders "
                "(id INTEGER PRIMARY KEY, customer_id INTEGER, status TEXT)"
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
            results[label] = lookup(db, customer_id, status) == expected

    return results


def main() -> None:
    results = check_customer_order_lookup(lookup_orders)

    for label, passed in results.items():
        print(f"{label}: {'PASS' if passed else 'FAIL'}")

    if not all(results.values()):
        raise SystemExit(1)

    print(f"All {len(results)} customer order lookup checks passed.")


if __name__ == "__main__":
    main()