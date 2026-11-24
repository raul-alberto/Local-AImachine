"""Tests for how the users database connection is configured.

Concurrent writes come from the request that saves a chat and the one that
updates a login throttle, so the connection needs WAL and a busy timeout rather
than failing with "database is locked".
"""

import sqlite3
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as court  # noqa: E402  (path bootstrap must run first)


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(court, 'USER_DB_FILE', str(tmp_path / 'users.db'))
    court.init_user_db()
    court.create_user('alice', 'password123', 'Alice')
    return Path(court.USER_DB_FILE)


def test_connections_enable_wal_busy_timeout_and_foreign_keys(db):
    conn = court._connect_user_db()
    try:
        assert conn.execute('PRAGMA journal_mode').fetchone()[0] == 'wal'
        assert conn.execute('PRAGMA busy_timeout').fetchone()[0] == court.USER_DB_TIMEOUT_SECONDS * 1000
        assert conn.execute('PRAGMA foreign_keys').fetchone()[0] == 1
    finally:
        conn.close()


def test_wal_is_stored_in_the_database_file(db):
    court._connect_user_db().close()

    raw = sqlite3.connect(db)
    try:
        assert raw.execute('PRAGMA journal_mode').fetchone()[0] == 'wal'
    finally:
        raw.close()


def test_foreign_keys_are_enforced(db):
    conn = court._connect_user_db()
    try:
        conn.execute('CREATE TABLE probe (user_id INTEGER REFERENCES users(id))')
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute('INSERT INTO probe (user_id) VALUES (999)')
    finally:
        conn.close()


def test_init_stamps_the_schema_version(db):
    conn = court._connect_user_db()
    try:
        assert conn.execute('PRAGMA user_version').fetchone()[0] == court.SCHEMA_VERSION
    finally:
        conn.close()


def test_existing_database_without_a_stamp_is_upgraded(tmp_path, monkeypatch):
    path = tmp_path / 'users.db'
    monkeypatch.setattr(court, 'USER_DB_FILE', str(path))
    raw = sqlite3.connect(path)
    raw.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')
    raw.execute(
        "INSERT INTO users (username, password_hash, display_name, created_at)"
        " VALUES ('old', 'hash', 'Old', '2024-01-01')"
    )
    raw.commit()
    raw.close()

    court.init_user_db()

    conn = court._connect_user_db()
    try:
        columns = {row[1] for row in conn.execute('PRAGMA table_info(users)')}
        assert 'session_version' in columns
        assert conn.execute('PRAGMA user_version').fetchone()[0] == court.SCHEMA_VERSION
        assert conn.execute('SELECT session_version FROM users').fetchone()[0] == 0
    finally:
        conn.close()


def test_a_second_writer_waits_instead_of_failing(db):
    holder = court._connect_user_db()
    holder.execute('BEGIN IMMEDIATE')
    holder.execute("UPDATE users SET display_name = 'Held' WHERE username = 'alice'")

    started = threading.Event()
    waited = {}

    def contender():
        conn = court._connect_user_db()
        try:
            started.set()
            began = time.monotonic()
            conn.execute("UPDATE users SET display_name = 'Waited' WHERE username = 'alice'")
            conn.commit()
            waited['seconds'] = time.monotonic() - began
        finally:
            conn.close()

    thread = threading.Thread(target=contender)
    thread.start()
    assert started.wait(timeout=5)
    time.sleep(0.2)  # let the contender run into the lock
    holder.commit()
    holder.close()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert waited['seconds'] >= 0.1  # waited for the lock instead of raising
    assert court.get_user_by_username('alice')['display_name'] == 'Waited'
