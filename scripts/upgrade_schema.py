"""Ensure SQLite schema contains columns introduced after initial release."""
from __future__ import annotations

import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_CANDIDATES = [
    ROOT / "data" / "lost_and_found.db",
    ROOT / "lost_and_found.db",
]


def ensure_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> bool:
    cursor = conn.execute(f"PRAGMA table_info({table})")
    columns = {row[1] for row in cursor.fetchall()}
    if column in columns:
        return False
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
    return True


def resolve_db_path() -> Path:
    for path in DB_CANDIDATES:
        if path.exists():
            return path
    raise SystemExit(
        "Database not found. Checked: " + ", ".join(str(path) for path in DB_CANDIDATES)
    )


def main() -> None:
    db_path = resolve_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.isolation_level = None  # autocommit each statement
        created = []
        if ensure_column(conn, "lost_items", "image_path", "VARCHAR(255)"):
            created.append("lost_items.image_path")
        if ensure_column(conn, "found_items", "image_path", "VARCHAR(255)"):
            created.append("found_items.image_path")

    if created:
        print("Added columns:", ", ".join(created))
    else:
        print("Schema already up to date.")


if __name__ == "__main__":
    main()
