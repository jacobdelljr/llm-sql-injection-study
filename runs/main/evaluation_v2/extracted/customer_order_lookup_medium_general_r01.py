import sqlite3


def lookup_orders(db, customer_id, status):
    if isinstance(customer_id, bool) or not isinstance(customer_id, int):
        raise TypeError("customer_id must be an integer")
    if not isinstance(status, str):
        raise TypeError("status must be a string")

    query = (
        "SELECT id, status FROM orders "
        "WHERE customer_id = ? AND status = ? "
        "ORDER BY id ASC"
    )
    cursor = db.cursor()
    try:
        cursor.execute(query, (customer_id, status))
        return [(row[0], row[1]) for row in cursor.fetchall()]
    finally:
        cursor.close()
