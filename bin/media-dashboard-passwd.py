#!/usr/bin/env python3
"""Manage dashboard accounts from the shell.

    media-dashboard-passwd.py                      set password for 'admin'
    media-dashboard-passwd.py <user>               set password for <user>
    media-dashboard-passwd.py <user> --random      generate one and print it
    media-dashboard-passwd.py --list               list accounts and roles
    media-dashboard-passwd.py <user> --role admin|user
    media-dashboard-passwd.py <user> --delete

Everything here is also doable in the web UI at /users (admins only).
"""
import base64
import getpass
import hashlib
import json
import os
import re
import secrets
import sys

AUTH_FILE = "/etc/media-dashboard/auth.json"
USERNAME_OK = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


def load():
    try:
        with open(AUTH_FILE) as f:
            a = json.load(f)
    except FileNotFoundError:
        a = {}
    if "users" not in a:
        # Migrate the original single-password layout.
        users = {}
        if a.get("salt") and a.get("hash"):
            users["admin"] = {"salt": a["salt"], "hash": a["hash"], "role": "admin"}
        a = {"secret": a.get("secret") or secrets.token_hex(32), "users": users}
    return a


def save(a):
    os.makedirs(os.path.dirname(AUTH_FILE), mode=0o700, exist_ok=True)
    tmp = AUTH_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(a, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, AUTH_FILE)


def hash_pw(pw):
    salt = os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return base64.b64encode(salt).decode(), base64.b64encode(dk).decode()


def main():
    args = sys.argv[1:]
    a = load()
    users = a.setdefault("users", {})

    if "--list" in args:
        if not users:
            print("no accounts")
        for n in sorted(users):
            print(f"{n}\t{users[n].get('role', 'user')}")
        return

    user = next((x for x in args if not x.startswith("-")), "admin")
    if not USERNAME_OK.match(user):
        sys.exit("invalid username")

    if "--delete" in args:
        admins = [u for u, v in users.items() if v.get("role") == "admin"]
        if user not in users:
            sys.exit("no such user")
        if users[user].get("role") == "admin" and admins == [user]:
            sys.exit("refusing to delete the last admin")
        del users[user]
        save(a)
        print(f"deleted {user}")
        return

    if "--role" in args:
        role = args[args.index("--role") + 1]
        if role not in ("admin", "user"):
            sys.exit("role must be 'admin' or 'user'")
        if user not in users:
            sys.exit("no such user")
        admins = [u for u, v in users.items() if v.get("role") == "admin"]
        if role != "admin" and admins == [user]:
            sys.exit("refusing to demote the last admin")
        users[user]["role"] = role
        save(a)
        print(f"{user} is now {role}")
        return

    # set / create password
    if "--random" in args:
        pw = secrets.token_urlsafe(18)
    else:
        pw = getpass.getpass(f"New password for {user}: ")
        if pw != getpass.getpass("Repeat: "):
            sys.exit("passwords do not match")
    if len(pw) < 8:
        sys.exit("password must be at least 8 characters")

    salt, h = hash_pw(pw)
    existing = users.get(user, {})
    users[user] = {"salt": salt, "hash": h,
                   "role": existing.get("role", "admin" if not users else "user")}
    save(a)
    if "--random" in args:
        print(pw)
    print(f"password set for {user} (role: {users[user]['role']})", file=sys.stderr)


if __name__ == "__main__":
    main()
