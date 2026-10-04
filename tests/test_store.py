"""
Unit tests for secure_store.py

Run from the project folder:  python -m unittest -v
"""

import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_store import (SALT_BYTES, UserStore, generate_salt,  # noqa: E402
                          hash_password)


class HashTests(unittest.TestCase):
    def test_salt_length(self):
        self.assertEqual(len(generate_salt()), SALT_BYTES)

    def test_salts_unique(self):
        salts = {generate_salt() for _ in range(1000)}
        self.assertEqual(len(salts), 1000)

    def test_known_sha256_vector(self):
        # known SHA-256 test vector: SHA-256("abc")
        self.assertEqual(
            hash_password("ab", b"c"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_same_salt_same_hash(self):
        salt = generate_salt()
        self.assertEqual(hash_password("Summer2026", salt),
                         hash_password("Summer2026", salt))

    def test_new_salt_new_hash(self):
        self.assertNotEqual(hash_password("Summer2026", generate_salt()),
                            hash_password("Summer2026", generate_salt()))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.db = os.path.join(tempfile.mkdtemp(), "test.db")
        self.store = UserStore(self.db)

    def test_register_and_login(self):
        self.assertTrue(self.store.register("alice", "Summer2026")[0])
        self.assertTrue(self.store.verify("alice", "Summer2026"))

    def test_wrong_password(self):
        self.store.register("alice", "Summer2026")
        self.assertFalse(self.store.verify("alice", "summer2026"))
        self.assertFalse(self.store.verify("alice", ""))

    def test_unknown_user(self):
        self.assertFalse(self.store.verify("nobody", "Summer2026"))

    def test_duplicate_username(self):
        self.store.register("alice", "Summer2026")
        ok, _ = self.store.register("alice", "Another123")
        self.assertFalse(ok)

    def test_weak_password(self):
        self.assertFalse(self.store.register("alice", "short1")[0])
        self.assertFalse(self.store.register("alice", "onlyletters")[0])

    def test_bad_username(self):
        self.assertFalse(self.store.register("a", "Summer2026")[0])
        self.assertFalse(self.store.register("bad name!", "Summer2026")[0])

    def test_same_password_two_users(self):
        self.store.register("alice", "Summer2026")
        self.store.register("bob", "Summer2026")
        a, b = self.store.list_users()
        self.assertNotEqual(a["salt"], b["salt"])
        self.assertNotEqual(a["password_hash"], b["password_hash"])

    def test_no_plaintext_in_db_file(self):
        self.store.register("alice", "Summer2026")
        with open(self.db, "rb") as f:
            self.assertNotIn(b"Summer2026", f.read())

    def test_sql_injection(self):
        self.store.register("alice", "Summer2026")
        self.assertFalse(self.store.verify("alice' OR '1'='1", "x"))
        self.assertFalse(self.store.verify("alice", "' OR '1'='1"))
        con = sqlite3.connect(self.db)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)
        con.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
