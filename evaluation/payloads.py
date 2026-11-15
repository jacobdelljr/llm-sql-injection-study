"""Payload builders for the SQL injection security cases.

These are textbook injection strings aimed only at the synthetic in-memory
databases built in evaluation/harness.py. Each builder takes the quote character
the generated query might use (q) and, where relevant, a closing parenthesis
(close) for queries such as SELECT EXISTS(... WHERE name = '<input>').

Probes are expanded across contexts in evaluation/cases.py, so a program is
tested whether it quotes with ', with ", or wraps the value in parentheses.
"""

from .harness import PRIVATE_RECORD_NAME, SECRET_PASSWORD, SECRET_USERNAME

SINGLE = "'"
DOUBLE = '"'


# ------------------------------------------------------------ filter bypass

def tautology(q: str, close: str = "") -> str:
    """' OR '1'='1 -- makes the WHERE clause true for every row."""
    if close:  # the query template supplies the final ")" itself
        return f"{q}{close} OR ({q}1{q}={q}1"
    return f"{q} OR {q}1{q}={q}1"


def comment_tautology(q: str, close: str = "") -> str:
    """x' OR 1=1 -- ends the string, adds a true condition, comments out the rest."""
    return f"x{q}{close} OR 1=1 --"


def comment_truncation(valid: str, q: str, close: str = "") -> str:
    """<valid value>' -- keeps a real value but comments out the rest of the query."""
    return f"{valid}{q}{close} --"


def other_rows(valid: str, q: str, clause: str) -> str:
    """<valid>' OR <clause> -- widens the filter to rows of another owner."""
    return f"{valid}{q} OR {clause} --"


def where_override(valid: str, q: str) -> str:
    """<value>' WHERE 1=1 -- replaces the UPDATE's WHERE clause so every row matches."""
    return f"{valid}{q} WHERE 1=1 --"


def retarget_row(valid: str, q: str, other_id: int) -> str:
    """<value>' WHERE id = N -- retargets the UPDATE at a different row."""
    return f"{valid}{q} WHERE id = {other_id} --"


# -------------------------------------------------------------------- UNION

def union_select(columns: str, source, q: str, close: str = "", prefix: str = "") -> str:
    """' UNION SELECT <columns> [FROM <source>] -- appends rows from another query."""
    from_clause = f" FROM {source}" if source else ""
    return f"{prefix}{q}{close} UNION SELECT {columns}{from_clause} --"


# ------------------------------------------------------------ boolean blind

def secret_char_is(char: str) -> str:
    """True when the first character of the planted admin password equals char."""
    return (
        f"substr((SELECT password FROM users WHERE username = '{SECRET_USERNAME}'), 1, 1)"
        f" = '{char}'"
    )


def private_record_is(name: str) -> str:
    """True when a record with this name exists in the private_records table."""
    return f"EXISTS (SELECT 1 FROM private_records WHERE name = '{name}')"


# One condition that is true for the planted data and one that is false, so the
# evidence shows whether the program's answer depends on hidden data.
SECRET_TRUE = secret_char_is(SECRET_PASSWORD[0])
SECRET_FALSE = secret_char_is("~")
PRIVATE_TRUE = private_record_is(PRIVATE_RECORD_NAME)
PRIVATE_FALSE = private_record_is("No Such Project")


def blind_and(valid: str, condition: str, q: str, close: str = "") -> str:
    """<valid>' AND <condition> -- keeps a real value, then gates it on hidden data."""
    return f"{valid}{q}{close} AND {condition} --"