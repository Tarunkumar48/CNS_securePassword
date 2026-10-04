"""
secure_store.py - core of the Secure Password Storage System.

Microproject 5, Cryptography and Network Security (E1CSA311).

What this module does
---------------------
* never stores a password in plain text
* generates a fresh random salt for every password with os.urandom()
* stores only  SHA-256(password || salt)  together with the salt
* verifies a login by re-hashing the entered password with the stored salt
  and comparing the two digests in constant time

Only the Python standard library is used (hashlib, os, hmac, sqlite3).
"""

import hashlib
import hmac
import os
import re
import sqlite3
from datetime import datetime

SALT_BYTES = 16          # 128-bit salt
MIN_PASSWORD_LENGTH = 8
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")


# ---------------------------------------------------------------- hashing --

def generate_salt(length=SALT_BYTES):
    """Return `length` cryptographically secure random bytes."""
    return os.urandom(length)


def hash_password(password, salt):
    """Return the hex SHA-256 digest of the password with the salt appended."""
    return hashlib.sha256(password.encode("utf-8") + salt).hexdigest()


def hash_unsalted(password):
    """Plain SHA-256 with no salt. Used only by the demos to show the weakness."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# ------------------------------------------------------------- validation --

def check_username(username):
    """Return an error message, or None if the username is acceptable."""
    if not USERNAME_PATTERN.match(username or ""):
        return "Username must be 3-30 characters: letters, digits, '_', '.' or '-'."
    return None


def check_password(password):
    """Return an error message, or None if the password meets the policy."""
    if len(password or "") < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Password must contain at least one letter and one digit."
    return None


# ---------------------------------------------------------------- storage --

class UserStore:
    """SQLite-backed table of (username, salt, salted hash)."""

    def __init__(self, db_path=DEFAULT_DB):
        self.db_path = db_path
        with self._connect() as con:
            con.execute(
                """CREATE TABLE IF NOT EXISTS users (
                       id            INTEGER PRIMARY KEY AUTOINCREMENT,
                       username      TEXT UNIQUE NOT NULL,
                       salt          TEXT NOT NULL,
                       password_hash TEXT NOT NULL,
                       created_at    TEXT NOT NULL
                   )"""
            )

    def _connect(self):
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        return con

    def register(self, username, password):
        """Create an account. Returns (ok, message)."""
        username = (username or "").strip()
        error = check_username(username) or check_password(password)
        if error:
            return False, error

        salt = generate_salt()
        digest = hash_password(password, salt)
        try:
            with self._connect() as con:
                # parameterised query -> no SQL injection
                con.execute(
                    "INSERT INTO users (username, salt, password_hash, created_at) "
                    "VALUES (?, ?, ?, ?)",
                    (username, salt.hex(), digest,
                     datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                )
        except sqlite3.IntegrityError:
            return False, "That username is already taken."
        return True, "Account created."

    def verify(self, username, password):
        """Return True only if the username exists and the password matches."""
        with self._connect() as con:
            row = con.execute(
                "SELECT salt, password_hash FROM users WHERE username = ?",
                ((username or "").strip(),),
            ).fetchone()

        if row is None:
            # Do the same amount of work for an unknown user, so response
            # time does not reveal which usernames exist.
            hash_password(password or "", generate_salt())
            return False

        salt = bytes.fromhex(row["salt"])
        candidate = hash_password(password or "", salt)
        # constant-time comparison prevents timing attacks on the digest
        return hmac.compare_digest(candidate, row["password_hash"])

    def list_users(self):
        """Return every stored record. There is no password column to return."""
        with self._connect() as con:
            rows = con.execute(
                "SELECT id, username, salt, password_hash, created_at "
                "FROM users ORDER BY id"
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_all(self):
        with self._connect() as con:
            con.execute("DELETE FROM users")
