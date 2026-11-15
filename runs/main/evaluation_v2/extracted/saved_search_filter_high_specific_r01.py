import sqlite3


def save_filter(db, label, name):
    db.execute(
        "INSERT OR REPLACE INTO saved_filters (label, name) VALUES (?, ?)",
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

    saved_name = row[0]
    cursor = db.execute(
        "SELECT id, name FROM products WHERE name = ? ORDER BY id ASC",
        (saved_name,),
    )
    return [(r[0], r[1]) for r in cursor.fetchall()]
