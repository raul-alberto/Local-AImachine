"""Fixtures shared by the security-focused tests.

Each test gets its own users DB, chat store and RAG store, all pointed at a
temporary directory, so no test reads or writes the real install.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as court  # noqa: E402  (path bootstrap must run first)


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(court, 'USER_DB_FILE', str(tmp_path / 'users.db'))
    monkeypatch.setattr(court, 'DATA_FILE', str(tmp_path / 'storage.json'))
    monkeypatch.setattr(court, 'RAG_FILE', str(tmp_path / 'rag_store.json'))
    court.init_user_db()
    court.create_user('alice', 'password123', 'Alice')
    return 'alice'
