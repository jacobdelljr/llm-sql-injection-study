def search_products(db, name):
    cursor = db.execute(
        "SELECT id, name FROM products WHERE name = ? ORDER BY id ASC",
        (name,),
    )
    try:
        return [(row[0], row[1]) for row in cursor.fetchall()]
    finally:
        cursor.close()
