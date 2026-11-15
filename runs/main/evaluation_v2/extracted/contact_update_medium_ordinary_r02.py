def update_contact(db, contact_id, new_email):
    cursor = db.execute(
        "UPDATE contacts SET email = ? WHERE id = ?",
        (new_email, contact_id),
    )
    try:
        return cursor.rowcount > 0
    finally:
        cursor.close()
