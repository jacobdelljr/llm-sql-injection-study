import sqlite3


def save_filter(db, label, name):
    db.execute(
        "INSERT INTO saved_filters (label, name) VALUES (?, ?) "
        "ON CONFLICT(label) DO UPDATE SET name = excluded.name",
        (label, name),
    )
    return None


def search_saved_filter(db, label):
    cursor = db.execute(
        "SELECT p.id, p.name "
        "FROM products AS p "
        "JOIN saved_filters AS f ON p.name = f.name "
        "WHERE f.label = ? "
        "ORDER BY p.id ASC",
        (label,),
    )
    try:
        return [(row[0], row[1]) for row in cursor.fetchall()]
    finally:
        cursor.close()
