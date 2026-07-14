"""
Incident Database Manager

Provides persistent storage for detected security incidents using SQLite,
so incidents survive Streamlit restarts and can be reviewed, filtered, and
tracked through an investigation workflow (Open -> Investigating -> Resolved).

This is intentionally dependency-free (uses the sqlite3 standard library
module only) so it does not add anything to requirements.txt.
"""

import sqlite3
import os
from datetime import datetime

DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "soc_incidents.db")


def _clean_value(value):
    """
    Guards against any value that ended up stored as raw bytes instead of
    a proper string (e.g. from an API response that was saved without
    being decoded first). SQLite will happily store bytes as a BLOB, and
    reading it back later hands you bytes again — which crashes anything
    downstream (like Streamlit's dataframe renderer) expecting text.

    Decodes bytes to text if possible, replacing any characters that
    can't be decoded rather than raising. Leaves every other type alone.
    """

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    return value


def _clean_text_param(value):
    """
    Guards against ever writing bytes into a TEXT column in the first
    place. If a caller accidentally passes bytes (e.g. an unconverted
    API response), this converts it to a proper string before it reaches
    the database.
    """

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    return value


def _clean_int_param(value):
    """
    Coerces a value to a plain Python int before it reaches the database.

    Handles numpy scalar types (e.g. numpy.int64 from a pandas DataFrame
    row) safely, and falls back to None instead of silently storing raw
    bytes if the value can't be interpreted as a number.
    """

    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _clean_float_param(value):
    """
    Coerces a value to a plain Python float before it reaches the
    database, for the same reasons as _clean_int_param.
    """

    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def get_connection():
    """
    Ensures the data directory exists and returns a SQLite connection
    configured to return rows that behave like dictionaries.
    """

    os.makedirs(DB_DIR, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    return conn


def init_db():
    """
    Creates the incidents table if it does not already exist.

    Safe to call multiple times / on every app startup.
    """

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detected_at TEXT NOT NULL,
            destination_port INTEGER,
            flow_duration REAL,
            prediction TEXT,
            risk TEXT,
            attack_type TEXT,
            tactic TEXT,
            technique TEXT,
            technique_id TEXT,
            description TEXT,
            mitigation TEXT,
            gemini_explanation TEXT,
            status TEXT NOT NULL DEFAULT 'Open'
        )
    """)

    conn.commit()
    conn.close()


def insert_incident(
        destination_port,
        flow_duration,
        prediction,
        risk,
        attack_type=None,
        tactic=None,
        technique=None,
        technique_id=None,
        description=None,
        mitigation=None,
        gemini_explanation=None,
        status="Open"):
    """
    Inserts a new incident record and returns its generated id.
    """

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO incidents (
            detected_at, destination_port, flow_duration, prediction, risk,
            attack_type, tactic, technique, technique_id, description,
            mitigation, gemini_explanation, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        _clean_int_param(destination_port),
        _clean_float_param(flow_duration),
        _clean_text_param(prediction),
        _clean_text_param(risk),
        _clean_text_param(attack_type),
        _clean_text_param(tactic),
        _clean_text_param(technique),
        _clean_text_param(technique_id),
        _clean_text_param(description),
        _clean_text_param(mitigation),
        _clean_text_param(gemini_explanation),
        _clean_text_param(status),
    ))

    incident_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return incident_id


def get_all_incidents(status=None, risk=None):
    """
    Returns stored incidents as a list of dicts, most recent first.

    Optionally filtered by status ("Open", "Investigating", "Resolved")
    and/or risk level. Pass "All" or None to skip a filter.
    """

    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM incidents"
    filters = []
    params = []

    if status and status != "All":
        filters.append("status = ?")
        params.append(status)

    if risk and risk != "All":
        filters.append("risk = ?")
        params.append(risk)

    if filters:
        query += " WHERE " + " AND ".join(filters)

    query += " ORDER BY id DESC"

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    return [
        {key: _clean_value(value) for key, value in dict(row).items()}
        for row in rows
    ]


def get_incident_by_id(incident_id):
    """
    Returns a single incident as a dict, or None if it does not exist.
    """

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    return {key: _clean_value(value) for key, value in dict(row).items()}


def update_incident_status(incident_id, status):
    """
    Updates the workflow status of an incident.
    """

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE incidents SET status = ? WHERE id = ?",
        (status, incident_id)
    )

    conn.commit()
    conn.close()


def delete_incident(incident_id):
    """
    Permanently deletes a single incident record.
    """

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))

    conn.commit()
    conn.close()


def get_incident_stats():
    """
    Returns summary counts used by the Incident Management KPI cards.
    """

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM incidents")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM incidents WHERE status = 'Open'")
    open_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM incidents WHERE status = 'Investigating'"
    )
    investigating_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM incidents WHERE status = 'Resolved'"
    )
    resolved_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM incidents WHERE risk LIKE '%High%'"
    )
    high_risk = cursor.fetchone()[0]

    conn.close()

    return {
        "total": total,
        "open": open_count,
        "investigating": investigating_count,
        "resolved": resolved_count,
        "high_risk": high_risk,
    }