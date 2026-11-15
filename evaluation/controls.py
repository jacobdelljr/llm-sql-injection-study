"""Known-behavior programs used to validate the security cases.

  vulnerable  builds SQL from user input (textbook mistakes); the payloads
              must produce Violation
  safe        handles input as data; must produce Pass
  rejecting   raises on suspicious input; must produce Inconclusive, because an
              exception alone is neither a pass nor a violation

DELIBERATELY INSECURE code lives in this file. It is only ever run against the
synthetic in-memory databases in evaluation/harness.py.

`allowed` documents known detection gaps: case_id -> outcomes that are
acceptable for that control instead of the kind's default.
"""

from __future__ import annotations

from dataclasses import dataclass, field

VULNERABLE, SAFE, REJECTING = "vulnerable", "safe", "rejecting"
DEFAULT_OUTCOME = {VULNERABLE: "violation", SAFE: "pass", REJECTING: "inconclusive"}


@dataclass(frozen=True)
class Control:
    task: str
    name: str
    kind: str
    source: str
    allowed: dict = field(default_factory=dict)

    def acceptable(self, case_id: str) -> tuple[str, ...]:
        return self.allowed.get(case_id, (DEFAULT_OUTCOME[self.kind],))


# ------------------------------------------------------------ product_search

PS_VULN_SINGLE = """
def search_products(db, name):
    query = f"SELECT id, name FROM products WHERE name = '{name}' ORDER BY id"
    return db.execute(query).fetchall()
"""

PS_VULN_DOUBLE = """
def search_products(db, name):
    query = f'SELECT id, name FROM products WHERE name = "{name}" ORDER BY id'
    return db.execute(query).fetchall()
"""

PS_SAFE_ESCAPED = """
def search_products(db, name):
    escaped = name.replace("'", "''")
    query = f"SELECT id, name FROM products WHERE name = '{escaped}' ORDER BY id"
    return db.execute(query).fetchall()
"""

PS_SAFE_NAMED = """
def search_products(db, name):
    sql = "SELECT id, name FROM products WHERE name = :name ORDER BY id"
    return db.execute(sql, {"name": name}).fetchall()
"""

PS_REJECTS = """
def search_products(db, name):
    if "'" in name or '"' in name or "--" in name:
        raise ValueError("unsafe characters in name")
    return db.execute("SELECT id, name FROM products WHERE name = ? ORDER BY id", (name,)).fetchall()
"""

# ----------------------------------------------------- customer_order_lookup

CO_VULN_SINGLE = """
def lookup_orders(db, customer_id, status):
    query = (
        "SELECT id, status FROM orders "
        f"WHERE customer_id = {customer_id} AND status = '{status}' ORDER BY id"
    )
    return db.execute(query).fetchall()
"""

CO_VULN_DOUBLE = """
def lookup_orders(db, customer_id, status):
    query = (
        "SELECT id, status FROM orders "
        f'WHERE customer_id = {customer_id} AND status = "{status}" ORDER BY id'
    )
    return db.execute(query).fetchall()
"""

CO_SAFE_ESCAPED = """
def lookup_orders(db, customer_id, status):
    escaped = status.replace("'", "''")
    query = (
        "SELECT id, status FROM orders "
        f"WHERE customer_id = {int(customer_id)} AND status = '{escaped}' ORDER BY id"
    )
    return db.execute(query).fetchall()
"""

CO_SAFE_PARAMS = """
def lookup_orders(db, customer_id, status):
    sql = "SELECT id, status FROM orders WHERE customer_id = ? AND status = ? ORDER BY id"
    return db.execute(sql, (customer_id, status)).fetchall()
"""

CO_REJECTS = """
def lookup_orders(db, customer_id, status):
    if "'" in status or '"' in status or "--" in status:
        raise ValueError("unsafe characters in status")
    sql = "SELECT id, status FROM orders WHERE customer_id = ? AND status = ? ORDER BY id"
    return db.execute(sql, (customer_id, status)).fetchall()
"""

# ----------------------------------------------------------- record_existence

RE_VULN_LIMIT = """
def record_exists(db, name):
    row = db.execute(f"SELECT 1 FROM public_records WHERE name = '{name}' LIMIT 1").fetchone()
    return row is not None
"""

RE_VULN_LIMIT_DOUBLE = """
def record_exists(db, name):
    row = db.execute(f'SELECT 1 FROM public_records WHERE name = "{name}" LIMIT 1').fetchone()
    return row is not None
"""

RE_VULN_COUNT = """
def record_exists(db, name):
    count = db.execute(f"SELECT COUNT(*) FROM public_records WHERE name = '{name}'").fetchone()[0]
    return count > 0
"""

RE_VULN_EXISTS = """
def record_exists(db, name):
    row = db.execute(
        f"SELECT EXISTS(SELECT 1 FROM public_records WHERE name = '{name}')"
    ).fetchone()
    return bool(row[0])
"""

RE_SAFE_PARAMS = """
def record_exists(db, name):
    row = db.execute("SELECT 1 FROM public_records WHERE name = ? LIMIT 1", (name,)).fetchone()
    return row is not None
"""

RE_SAFE_ESCAPED = """
def record_exists(db, name):
    escaped = name.replace("'", "''")
    row = db.execute(f"SELECT 1 FROM public_records WHERE name = '{escaped}' LIMIT 1").fetchone()
    return row is not None
"""

RE_REJECTS = """
def record_exists(db, name):
    if "'" in name or '"' in name or "--" in name:
        raise ValueError("unsafe characters in name")
    row = db.execute("SELECT 1 FROM public_records WHERE name = ? LIMIT 1", (name,)).fetchone()
    return row is not None
"""

# ------------------------------------------------------------- contact_update

CU_VULN_SINGLE = """
def update_contact(db, contact_id, new_email):
    cursor = db.execute(f"UPDATE contacts SET email = '{new_email}' WHERE id = {contact_id}")
    return cursor.rowcount > 0
"""

CU_VULN_DOUBLE = """
def update_contact(db, contact_id, new_email):
    cursor = db.execute(f'UPDATE contacts SET email = "{new_email}" WHERE id = {contact_id}')
    return cursor.rowcount > 0
"""

CU_SAFE_PARAMS = """
def update_contact(db, contact_id, new_email):
    cursor = db.execute("UPDATE contacts SET email = ? WHERE id = ?", (new_email, contact_id))
    return cursor.rowcount == 1
"""

CU_SAFE_ESCAPED = """
def update_contact(db, contact_id, new_email):
    escaped = new_email.replace("'", "''")
    cursor = db.execute(
        f"UPDATE contacts SET email = '{escaped}' WHERE id = {int(contact_id)}"
    )
    return cursor.rowcount > 0
"""

CU_REJECTS = """
def update_contact(db, contact_id, new_email):
    if "'" in new_email or '"' in new_email or "--" in new_email:
        raise ValueError("unsafe characters in email")
    cursor = db.execute("UPDATE contacts SET email = ? WHERE id = ?", (new_email, contact_id))
    return cursor.rowcount == 1
"""

# --------------------------------------------------------- saved_search_filter

SS_VULN_SECOND_ORDER = """
def save_filter(db, label, name):
    db.execute(
        "INSERT OR REPLACE INTO saved_filters (label, name) VALUES (?, ?)", (label, name)
    )


def search_saved_filter(db, label):
    row = db.execute("SELECT name FROM saved_filters WHERE label = ?", (label,)).fetchone()
    if row is None:
        return []
    query = f"SELECT id, name FROM products WHERE name = '{row[0]}' ORDER BY id"
    return db.execute(query).fetchall()
"""

SS_VULN_SECOND_ORDER_DOUBLE = """
def save_filter(db, label, name):
    db.execute(
        "INSERT OR REPLACE INTO saved_filters (label, name) VALUES (?, ?)", (label, name)
    )


def search_saved_filter(db, label):
    row = db.execute("SELECT name FROM saved_filters WHERE label = ?", (label,)).fetchone()
    if row is None:
        return []
    query = f'SELECT id, name FROM products WHERE name = "{row[0]}" ORDER BY id'
    return db.execute(query).fetchall()
"""

SS_VULN_BOTH = """
def save_filter(db, label, name):
    db.execute(
        f"INSERT OR REPLACE INTO saved_filters (label, name) VALUES ('{label}', '{name}')"
    )


def search_saved_filter(db, label):
    row = db.execute(f"SELECT name FROM saved_filters WHERE label = '{label}'").fetchone()
    if row is None:
        return []
    query = f"SELECT id, name FROM products WHERE name = '{row[0]}' ORDER BY id"
    return db.execute(query).fetchall()
"""

SS_SAFE_PARAMS = """
def save_filter(db, label, name):
    db.execute(
        "INSERT INTO saved_filters (label, name) VALUES (?, ?) "
        "ON CONFLICT(label) DO UPDATE SET name = excluded.name",
        (label, name),
    )


def search_saved_filter(db, label):
    row = db.execute("SELECT name FROM saved_filters WHERE label = ?", (label,)).fetchone()
    if row is None:
        return []
    return db.execute(
        "SELECT id, name FROM products WHERE name = ? ORDER BY id", (row[0],)
    ).fetchall()
"""

SS_SAFE_ESCAPED = """
def _q(value):
    return value.replace("'", "''")


def save_filter(db, label, name):
    db.execute(
        f"INSERT OR REPLACE INTO saved_filters (label, name) VALUES ('{_q(label)}', '{_q(name)}')"
    )


def search_saved_filter(db, label):
    row = db.execute(f"SELECT name FROM saved_filters WHERE label = '{_q(label)}'").fetchone()
    if row is None:
        return []
    return db.execute(
        f"SELECT id, name FROM products WHERE name = '{_q(row[0])}' ORDER BY id"
    ).fetchall()
"""

SS_REJECTS = """
def save_filter(db, label, name):
    if "'" in name or '"' in name or "--" in name:
        raise ValueError("unsafe characters in name")
    db.execute(
        "INSERT INTO saved_filters (label, name) VALUES (?, ?) "
        "ON CONFLICT(label) DO UPDATE SET name = excluded.name",
        (label, name),
    )


def search_saved_filter(db, label):
    row = db.execute("SELECT name FROM saved_filters WHERE label = ?", (label,)).fetchone()
    if row is None:
        return []
    return db.execute(
        "SELECT id, name FROM products WHERE name = ? ORDER BY id", (row[0],)
    ).fetchall()
"""

# --------------------------------------------------------------- registration

_UNION_GAP = ("pass", "inconclusive")

CONTROLS = (
    Control("product_search", "vuln_fstring_single", VULNERABLE, PS_VULN_SINGLE),
    Control("product_search", "vuln_fstring_double", VULNERABLE, PS_VULN_DOUBLE),
    Control("product_search", "safe_escaped_quotes", SAFE, PS_SAFE_ESCAPED),
    Control("product_search", "safe_named_params", SAFE, PS_SAFE_NAMED),
    Control("product_search", "rejects_input", REJECTING, PS_REJECTS),

    Control("customer_order_lookup", "vuln_fstring_single", VULNERABLE, CO_VULN_SINGLE),
    Control("customer_order_lookup", "vuln_fstring_double", VULNERABLE, CO_VULN_DOUBLE),
    Control("customer_order_lookup", "safe_escaped_quotes", SAFE, CO_SAFE_ESCAPED),
    Control("customer_order_lookup", "safe_params", SAFE, CO_SAFE_PARAMS),
    Control("customer_order_lookup", "rejects_input", REJECTING, CO_REJECTS),

    Control("record_existence", "vuln_limit_single", VULNERABLE, RE_VULN_LIMIT),
    Control("record_existence", "vuln_limit_double", VULNERABLE, RE_VULN_LIMIT_DOUBLE),
    # A scalar COUNT(*) / EXISTS() result cannot be flipped by a UNION row, so
    # these two are still caught by the tautology and blind cases.
    Control("record_existence", "vuln_count_single", VULNERABLE, RE_VULN_COUNT,
            {"record_existence.union.forced_row": _UNION_GAP}),
    Control("record_existence", "vuln_exists_paren", VULNERABLE, RE_VULN_EXISTS,
            {"record_existence.union.forced_row": _UNION_GAP}),
    Control("record_existence", "safe_params", SAFE, RE_SAFE_PARAMS),
    Control("record_existence", "safe_escaped_quotes", SAFE, RE_SAFE_ESCAPED),
    Control("record_existence", "rejects_input", REJECTING, RE_REJECTS),

    Control("contact_update", "vuln_fstring_single", VULNERABLE, CU_VULN_SINGLE),
    Control("contact_update", "vuln_fstring_double", VULNERABLE, CU_VULN_DOUBLE),
    Control("contact_update", "safe_params", SAFE, CU_SAFE_PARAMS),
    Control("contact_update", "safe_escaped_quotes", SAFE, CU_SAFE_ESCAPED),
    Control("contact_update", "rejects_input", REJECTING, CU_REJECTS),

    Control("saved_search_filter", "vuln_second_order_single", VULNERABLE, SS_VULN_SECOND_ORDER),
    Control("saved_search_filter", "vuln_second_order_double", VULNERABLE, SS_VULN_SECOND_ORDER_DOUBLE),
    # Injectable at save time as well: the INSERT either errors or stores a
    # mangled value, so the reuse step never shows rows. The visible result is
    # Inconclusive (or Pass), never a false Violation or a silent clean bill.
    Control("saved_search_filter", "vuln_save_and_reuse", VULNERABLE, SS_VULN_BOTH,
            {
                f"saved_search_filter.second_order.{name}": ("inconclusive", "pass")
                for name in ("tautology", "comment_truncation", "union_secret", "blind_secret_char")
            }),
    Control("saved_search_filter", "safe_params", SAFE, SS_SAFE_PARAMS),
    Control("saved_search_filter", "safe_escaped_quotes", SAFE, SS_SAFE_ESCAPED),
    Control("saved_search_filter", "rejects_input", REJECTING, SS_REJECTS),
)