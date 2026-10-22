import hashlib
import os
import tempfile
import time

from secure_store import UserStore, generate_salt, hash_password, hash_unsalted


def average_us(func, repeat, rounds=15):
    """Average time of func() in microseconds (best of several rounds,
    which filters out interference from other programs)."""
    for _ in range(repeat // 10):        # warm-up
        func()
    best = float("inf")
    for _ in range(rounds):
        start = time.perf_counter()
        for _ in range(repeat):
            func()
        best = min(best, (time.perf_counter() - start) / repeat * 1e6)
    return best


def main():
    results = {}
    print("PERFORMANCE ANALYSIS")
    print("=" * 62)

    # 1. primitive operations ------------------------------------------------
    salt = generate_salt()
    results["salt"] = average_us(generate_salt, 20_000)
    results["unsalted"] = average_us(lambda: hash_unsalted("Summer2026"), 20_000)
    results["salted"] = average_us(lambda: hash_password("Summer2026", salt), 20_000)
    print("\n1. Primitive operations (average of 20,000 runs, best of 15 rounds)")
    print(f"   os.urandom(16) salt generation : {results['salt']:8.3f} us")
    print(f"   SHA-256 without salt           : {results['unsalted']:8.3f} us")
    print(f"   SHA-256 with 16-byte salt      : {results['salted']:8.3f} us")

    # 2. hashing time against password length --------------------------------
    print("\n2. Salted SHA-256 time against password length")
    results["length"] = {}
    for n in (8, 16, 32, 64, 128, 256):
        pw = "a" * n
        t = average_us(lambda: hash_password(pw, salt), 20_000)
        results["length"][n] = t
        print(f"   {n:>4} characters : {t:6.3f} us")

    # 3. end-to-end operations -----------------------------------------------
    db = os.path.join(tempfile.mkdtemp(), "bench.db")
    store = UserStore(db)
    n_users = 200
    start = time.perf_counter()
    for i in range(n_users):
        store.register(f"user{i}", "Summer2026")
    results["register_ms"] = (time.perf_counter() - start) / n_users * 1e3
    start = time.perf_counter()
    for i in range(n_users):
        store.verify(f"user{i}", "Summer2026")
    results["login_ms"] = (time.perf_counter() - start) / n_users * 1e3
    print(f"\n3. End-to-end operations with SQLite (average of {n_users})")
    print(f"   register (salt + hash + INSERT) : {results['register_ms']:6.3f} ms")
    print(f"   login    (SELECT + hash + compare): {results['login_ms']:6.3f} ms")

    # 4. cost to the attacker -------------------------------------------------
    print("\n4. Attacker's work to test a dictionary against a stolen database")
    rate = 1e6 / results["salted"]
    print(f"   measured single-core rate: {rate:,.0f} hashes per second")
    results["attack"] = []
    words = 1_000_000
    for users in (1, 100, 10_000):
        unsalted = words                 # one table serves every user
        salted = words * users           # the dictionary is redone per salt
        results["attack"].append((users, unsalted, salted))
        print(f"   {users:>6} user(s), 1M-word dictionary: "
              f"unsalted {unsalted:>14,} hashes | salted {salted:>17,} hashes")

    # 5. key stretching, for comparison (future scope) -------------------------
    start = time.perf_counter()
    for _ in range(5):
        hashlib.pbkdf2_hmac("sha256", b"Summer2026", salt, 600_000)
    results["pbkdf2_ms"] = (time.perf_counter() - start) / 5 * 1e3
    print("\n5. For comparison: PBKDF2-HMAC-SHA256, 600,000 iterations")
    print(f"   one hash : {results['pbkdf2_ms']:.1f} ms "
          f"(about {results['pbkdf2_ms'] * 1000 / results['salted']:,.0f}x slower "
          "than a single SHA-256)")
    print()
    return results


if __name__ == "__main__":
    main()
