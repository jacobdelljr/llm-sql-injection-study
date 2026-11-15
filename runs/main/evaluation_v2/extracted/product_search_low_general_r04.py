import sqlite3


def search_products(db, name):
    if not isinstance(name, str):
        return []
    cursor = db.cursor()
    try:
        cursor.execute(
            "SELECT id, name FROM products WHERE name = ? ORDER BY id ASC",
            (name,),
        )
        return [(row[0], row[1]) for row in cursor.fetchall()]
    finally:
        cursor.close()
