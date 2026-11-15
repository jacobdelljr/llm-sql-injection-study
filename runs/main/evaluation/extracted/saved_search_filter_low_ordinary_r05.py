def save_filter(db, label, name):
    db.execute(
        "INSERT OR REPLACE INTO saved_filters (label, name) VALUES (?, ?)",
        (label, name),
    )
    return None


def search_saved_filter(db, label):
    row = db.execute(
        "SELECT name FROM saved_filters WHERE label = ?",
        (label,),
    ).fetchone()
    if row is None:
        return []
    cursor = db.execute(
        "SELECT id, name FROM products WHERE name = ? ORDER BY id ASC",
        (row[0],),
    )
    return [(r[0], r[1]) for r in cursor.fetchall()]
