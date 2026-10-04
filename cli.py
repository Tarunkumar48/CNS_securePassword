"""
cli.py - menu-driven terminal interface for the Secure Password Storage System.

Run:  python cli.py
"""

from getpass import getpass

from secure_store import UserStore

MENU = """
==============================================
      SECURE PASSWORD STORAGE SYSTEM
==============================================
  1. Register a new user
  2. Login
  3. View stored records (what the database holds)
  4. Exit
----------------------------------------------"""


def register(store):
    username = input("Choose a username : ")
    password = getpass("Choose a password : ")
    if password != getpass("Confirm password  : "):
        print("[!] Passwords do not match.")
        return
    ok, message = store.register(username, password)
    print(("[+] " if ok else "[!] ") + message)


def login(store):
    username = input("Username : ")
    password = getpass("Password : ")
    if store.verify(username, password):
        print(f"[+] Login successful. Welcome, {username}!")
    else:
        print("[!] Invalid username or password.")


def show_records(store):
    users = store.list_users()
    if not users:
        print("(no users registered yet)")
        return
    for u in users:
        print(f"\nUser #{u['id']}: {u['username']}   (created {u['created_at']})")
        print(f"  salt : {u['salt']}")
        print(f"  hash : {u['password_hash']}")
    print("\nNote: the original passwords are not stored anywhere.")


def main():
    store = UserStore()
    actions = {"1": register, "2": login, "3": show_records}
    while True:
        print(MENU)
        choice = input("Enter your choice: ").strip()
        if choice == "4":
            print("Goodbye.")
            break
        action = actions.get(choice)
        if action:
            action(store)
        else:
            print("[!] Please enter a number from 1 to 4.")


if __name__ == "__main__":
    main()
