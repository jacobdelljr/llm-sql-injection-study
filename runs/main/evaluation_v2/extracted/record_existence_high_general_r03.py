import sqlite3


def record_exists(db: sqlite3.Connection, name: str) -> bool:
    if not isinstance(name, str):
        return False

    cursor = db.cursor()
    try:
        cursor.execute(
            "SELECT EXISTS(SELECT 1 FROM public_records WHERE name = ? LIMIT 1)",
            (name,),
        )
        row = cursor.fetchone()
        return bool(row[0]) if row else False
    finally:
        cursor.close()
