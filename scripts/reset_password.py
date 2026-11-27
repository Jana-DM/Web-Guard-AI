import argparse
import sqlite3
import sys
from pathlib import Path

try:
    import bcrypt
except ImportError:
    print("Error: bcrypt not found. Run with .\\.venv\\Scripts\\python.exe")
    sys.exit(1)

DB_PATH = Path(__file__).resolve().parent.parent / "backend" / "webguard.db"


def reset_user_password(email_or_username: str, new_password: str) -> bool:
    if not DB_PATH.exists():
        print(f"Database not found at {DB_PATH}")
        return False

    salt = bcrypt.gensalt(12)
    hashed = bcrypt.hashpw(new_password.encode("utf-8"), salt).decode("utf-8")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET hashed_password = ? WHERE email = ? OR username = ?",
        (hashed, email_or_username.lower(), email_or_username),
    )
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()

    if updated:
        print(f"Password successfully reset for '{email_or_username}'!")
    else:
        print(f"User '{email_or_username}' not found in database.")
    return updated


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reset Web Guard AI user password")
    parser.add_argument("email_or_username", help="User email or username")
    parser.add_argument("new_password", help="New password to set")
    args = parser.parse_args()

    reset_user_password(args.email_or_username, args.new_password)
