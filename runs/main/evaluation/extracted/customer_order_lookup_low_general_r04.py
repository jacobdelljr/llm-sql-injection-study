import sqlite3


def lookup_orders(db, customer_id, status):
    query = (
        "SELECT id, status FROM orders "
        "WHERE customer_id = ? AND status = ? "
        "ORDER BY id ASC"
    )
    cursor = db.execute(query, (customer_id, status))
    try:
        return [(row[0], row[1]) for row in cursor.fetchall()]
    finally:
        cursor.close()
