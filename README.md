# Secure Password Storage System

Microproject 5 - Cryptography and Network Security (E1CSA311), Alliance University.

Passwords are never stored. For each account the system keeps a random 16-byte
salt from `os.urandom()` and `SHA-256(password + salt)` computed with `hashlib`.
At login the entered password is re-hashed with the stored salt and compared.

## Files

| File | Purpose |
|------|---------|
| `secure_store.py` | Core module: salt generation, hashing, SQLite storage, verification |
| `cli.py` | Menu-driven terminal program (register, login, view records) |
| `app.py` | Flask web interface (register, login, dashboard, stored records) |
| `demo.py` | Automatic demonstration of the security properties |
| `benchmark.py` | Timing measurements used in the report |
| `tests/test_store.py` | Unit tests |
| `templates/`, `static/` | HTML pages and stylesheet for the web interface |
| `report/` | Microproject report (Word and PDF) |
| `screenshots/` | Output images and diagrams used in the report |

## How to run (VS Code terminal)

```bash
python3 cli.py                               # terminal version
python3 demo.py                              # security demonstrations
python3 benchmark.py                         # performance figures
python3 -m unittest discover -s tests -v     # unit tests

pip3 install -r requirements.txt             # only needed for the web version
python3 app.py                               # then open http://127.0.0.1:5000
```

The core module, CLI, demo, benchmark and tests use only the Python standard
library. Flask is needed only for `app.py`.

User records are saved in `users.db` (created automatically on first run).
