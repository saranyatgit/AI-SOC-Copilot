"""
Authentication Module

Provides simple, dependency-free username/password authentication backed
by SQLite. Passwords are never stored in plain text: each password is
hashed with PBKDF2-HMAC-SHA256 using a unique random salt per user.

Deliberately does not support open self-registration after the first
account is created — a SOC tool should have analysts provisioned, not
signed up publicly. The very first run allows creating exactly one
admin account; after that, only login is available.
"""

import hashlib
import os
import secrets

from utils.incident_db import get_connection

PBKDF2_ITERATIONS = 100_000


def init_auth_db():
    """
    Creates the users table if it does not already exist.

    Safe to call multiple times / on every app startup.
    """

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def _hash_password(password, salt_hex=None):
    """
    Hashes a password with PBKDF2-HMAC-SHA256.

    If salt_hex is not provided, a new random salt is generated (used
    when creating an account). If salt_hex is provided, the same salt
    is reused (used when verifying a login attempt).

    Returns (password_hash_hex, salt_hex).
    """

    if salt_hex is None:
        salt_bytes = secrets.token_bytes(16)
    else:
        salt_bytes = bytes.fromhex(salt_hex)

    hash_bytes = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        PBKDF2_ITERATIONS,
    )

    return hash_bytes.hex(), salt_bytes.hex()


def any_users_exist():
    """
    Returns True if at least one user account already exists.

    Used to decide whether to show the one-time admin-creation form
    or the normal login form.
    """

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]

    conn.close()

    return count > 0


def create_user(username, password):
    """
    Creates a new user account.

    Returns True on success, False if the username is already taken.
    """

    username = username.strip()

    if not username or not password:
        return False

    password_hash, salt_hex = _hash_password(password)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt) "
            "VALUES (?, ?, ?)",
            (username, password_hash, salt_hex),
        )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()


def verify_login(username, password):
    """
    Checks a username/password combination against the stored, hashed
    credentials. Returns True if they match, False otherwise.
    """

    username = username.strip()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password_hash, salt FROM users WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return False

    stored_hash = row["password_hash"]
    salt_hex = row["salt"]

    candidate_hash, _ = _hash_password(password, salt_hex)

    return secrets.compare_digest(candidate_hash, stored_hash)