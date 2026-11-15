def save_filter(db, label, name):
    db.execute(
        "INSERT INTO saved_filters (label, name) VALUES (?, ?) "
        "ON CONFLICT(label) DO UPDATE SET name = excluded.name",
        (label, name),
    )
    return None


def search_saved_filter(db, label):
    cur = db.execute("SELECT name FROM saved_filters WHERE label = ?", (label,))
    row = cur.fetchone()
    cur.close()
    if row is None:
        return []
    cur = db.execute(
        "SELECT id, name FROM products WHERE name = ? ORDER BY id ASC",
        (row[0],),
    )
    results = [(r[0], r[1]) for r in cur.fetchall()]
    cur.close()
    return results
