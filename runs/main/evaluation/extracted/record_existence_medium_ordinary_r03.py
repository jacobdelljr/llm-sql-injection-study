def record_exists(db, name):
    cursor = db.execute(
        "SELECT 1 FROM public_records WHERE name = ? LIMIT 1",
        (name,),
    )
    try:
        return cursor.fetchone() is not None
    finally:
        cursor.close()
