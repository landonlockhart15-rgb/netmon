"""
set_password.py — One-time setup: generate a bcrypt hash for your NetMon password.

Run this once, copy the output into your .env file, then restart the server.

Usage:
  python tools/set_password.py
"""

import argparse
import getpass
import sys
from pathlib import Path

try:
    import bcrypt
except ImportError:
    print("ERROR: bcrypt not installed. Run: pip install bcrypt")
    sys.exit(1)

def _write_env(path: Path, values: dict[str, str]) -> None:
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    seen: set[str] = set()
    updated: list[str] = []

    for line in lines:
        stripped = line.lstrip()
        key = stripped.split("=", 1)[0].strip() if "=" in stripped else ""
        if key in values and not stripped.startswith("#"):
            updated.append(f"{key}={values[key]}")
            seen.add(key)
        else:
            updated.append(line)

    if updated and updated[-1].strip():
        updated.append("")

    for key, value in values.items():
        if key not in seen:
            updated.append(f"{key}={value}")

    path.write_text("\n".join(updated).rstrip() + "\n", encoding="utf-8")


parser = argparse.ArgumentParser(description="Set the NetMon dashboard login.")
parser.add_argument("--write", action="store_true", help="Write APP_USERNAME and APP_PASSWORD_HASH to .env")
parser.add_argument(
    "--env-file",
    default=str(Path(__file__).resolve().parents[1] / ".env"),
    help="Path to .env when using --write",
)
args = parser.parse_args()

print("NetMon - Set Password")
print("-" * 40)

username = input("Username (default: admin): ").strip() or "admin"

while True:
    password = getpass.getpass("Password: ")
    if len(password) < 8:
        print("Password must be at least 8 characters. Try again.")
        continue
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match. Try again.")
        continue
    break

hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

print()
print("-" * 40)
if args.write:
    env_path = Path(args.env_file)
    _write_env(env_path, {
        "APP_USERNAME": username,
        "APP_PASSWORD_HASH": hashed,
    })
    print(f"Saved dashboard login to {env_path}")
else:
    print("Add these lines to your .env file:")
    print("-" * 40)
    print(f"APP_USERNAME={username}")
    print(f"APP_PASSWORD_HASH={hashed}")
print("-" * 40)
print()
print("Then restart the server.")
