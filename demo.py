import os
import tempfile

from secure_store import UserStore, hash_password, hash_unsalted

LINE = "-" * 78
def title(text):
    print("\n" + LINE + "\n" + text + "\n" + LINE)


def main():
    db = os.path.join(tempfile.mkdtemp(), "demo.db")
    store = UserStore(db)

    # 1 ---------------------------------------------------------------------
    title("DEMO 1: Registration stores a salt and a hash, never the password")
    for name, pw in [("alice", "Summer2026"), ("bob", "Summer2026"),
                     ("charlie", "Tr1cky#Pass")]:
        ok, msg = store.register(name, pw)
        print(f"register({name!r}, {pw!r}) -> {msg}")
    print()
    for u in store.list_users():
        print(f"{u['username']:<8} salt={u['salt']}")
        print(f"{'':<8} hash={u['password_hash']}")

    # 2 ---------------------------------------------------------------------
    title("DEMO 2: Same password, different salts -> different hashes")
    a, b = store.list_users()[:2]
    print("alice and bob both chose the password 'Summer2026'")
    print("alice hash :", a["password_hash"])
    print("bob   hash :", b["password_hash"])
    print("hashes identical? ->", a["password_hash"] == b["password_hash"])
    print("\nWithout a salt both would be stored as:")
    print("             ", hash_unsalted("Summer2026"))

    # 3 ---------------------------------------------------------------------
    title("DEMO 3: Login verification by re-hashing with the stored salt")
    for name, pw in [("alice", "Summer2026"), ("alice", "summer2026"),
                     ("bob", "WrongPass1"), ("mallory", "Summer2026")]:
        result = "ACCESS GRANTED" if store.verify(name, pw) else "ACCESS DENIED"
        print(f"login({name!r}, {pw!r}) -> {result}")

    # 4 ---------------------------------------------------------------------
    title("DEMO 4: Rainbow-table (precomputed hash) attack")
    common = ["123456", "password", "qwerty123", "Summer2026", "iloveyou1",
              "admin123", "welcome1", "letmein12", "dragon2024", "monkey99"]
    table = {hash_unsalted(p): p for p in common}       # built once, reused
    print(f"Attacker precomputes SHA-256 of {len(common)} common passwords.\n")

    print("(a) Against a database of UNSALTED hashes:")
    unsalted_db = {"alice": hash_unsalted("Summer2026"),
                   "bob": hash_unsalted("Summer2026"),
                   "charlie": hash_unsalted("Tr1cky#Pass")}
    for user, digest in unsalted_db.items():
        found = table.get(digest)
        print(f"    {user:<8} -> " + (f"CRACKED: {found!r}" if found else "not in table"))

    print("\n(b) Against this system's SALTED hashes (same lookup table):")
    cracked = 0
    for u in store.list_users():
        found = table.get(u["password_hash"])
        cracked += bool(found)
        print(f"    {u['username']:<8} -> " + (f"CRACKED: {found!r}" if found else "not in table"))
    print(f"\n    Passwords recovered from the salted database: {cracked}")

    # 5 ---------------------------------------------------------------------
    title("DEMO 5: Avalanche effect of SHA-256")
    salt = bytes.fromhex(a["salt"])
    h1 = hash_password("Summer2026", salt)
    h2 = hash_password("Summer2027", salt)
    diff = bin(int(h1, 16) ^ int(h2, 16)).count("1")
    print("SHA-256('Summer2026' + salt) =", h1)
    print("SHA-256('Summer2027' + salt) =", h2)
    print(f"One character changed -> {diff} of 256 output bits differ "
          f"({diff / 256:.1%})")
    print()


if __name__ == "__main__":
    main()
