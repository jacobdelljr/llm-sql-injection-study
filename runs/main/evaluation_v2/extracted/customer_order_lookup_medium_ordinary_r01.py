def lookup_orders(db, customer_id, status):
    cursor = db.execute(
        "SELECT id, status FROM orders WHERE customer_id = ? AND status = ? ORDER BY id ASC",
        (customer_id, status),
    )
    try:
        return [(row[0], row[1]) for row in cursor.fetchall()]
    finally:
        cursor.close()
