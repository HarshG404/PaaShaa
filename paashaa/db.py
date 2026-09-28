"""SQLite storage layer (thread-safe, parameterised queries only)."""
from __future__ import annotations

import os
import sqlite3
import threading
from datetime import datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT NOT NULL, recovery TEXT,
    pw_hash TEXT NOT NULL, app_pw TEXT, photo TEXT, sched TEXT, next_due TEXT);
CREATE TABLE IF NOT EXISTS entries(
    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    site TEXT NOT NULL, username TEXT, login_email TEXT, method TEXT, descr TEXT, pw TEXT NOT NULL,
    changed_info TEXT, changed_at TEXT, in_sched INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS audit(
    id INTEGER PRIMARY KEY, user_id INTEGER, ts TEXT NOT NULL, event TEXT NOT NULL, detail TEXT);
CREATE INDEX IF NOT EXISTS idx_entries_user ON entries(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit(user_id, id DESC);
"""


class Database:
    def __init__(self, path: str):
        self._c = sqlite3.connect(path, check_same_thread=False)
        self._c.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._c.execute("PRAGMA foreign_keys=ON")
            if path != ":memory:":
                self._c.execute("PRAGMA journal_mode=WAL")
            self._c.executescript(SCHEMA)
            self._c.commit()
        if path != ":memory:":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass

    def q(self, sql: str, args=(), one: bool = False, commit: bool = False):
        with self._lock:
            cur = self._c.execute(sql, args)
            if commit:
                self._c.commit()
            return cur.fetchone() if one else cur.fetchall()

    def insert(self, sql: str, args=()) -> int:
        with self._lock:
            cur = self._c.execute(sql, args)
            self._c.commit()
            return cur.lastrowid

    def audit(self, user_id, event: str, detail: str = "") -> None:
        self.q("INSERT INTO audit(user_id,ts,event,detail) VALUES(?,?,?,?)",
               (user_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event, detail), commit=True)
