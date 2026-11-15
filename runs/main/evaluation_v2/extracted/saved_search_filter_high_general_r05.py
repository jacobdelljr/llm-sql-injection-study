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
        "SELECT name FROM saved_filters WHERE label = ?",
        (label,),
    )
    row = cursor.fetchone()
    if row is None:
        return []

    stored_name = row[0]
    cursor = db.execute(
        "SELECT id, name FROM products WHERE name = ? ORDER BY id ASC",
        (stored_name,),
    )
    return [(r[0], r[1]) for r in cursor.fetchall()]
