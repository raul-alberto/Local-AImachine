"""Tests for the per-install session signing key.

A predictable key would let anyone forge a session cookie and inject chat
HTML, so these lock in the properties that prevent it: no constant fallback,
a real random key persisted with owner-only permissions, and env override
support.
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as court  # noqa: E402  (path bootstrap must run first)


@pytest.fixture(autouse=True)
def no_key_env(monkeypatch):
    monkeypatch.delenv("COURT_SECRET_KEY", raising=False)
    monkeypatch.delenv("BETTEN_SECRET_KEY", raising=False)


def test_key_file_lives_beside_the_user_database():
    assert Path(court.SECRET_KEY_FILE).parent == Path(court.USER_DB_FILE).parent


def test_module_never_uses_a_constant_default():
    assert court.app.secret_key != "your_secret_key_here"
    assert len(court.app.secret_key) >= 32


def test_generates_a_key_once_then_reuses_it(tmp_path):
    path = tmp_path / ".court_secret"

    first = court.load_or_create_secret_key(str(path))
    assert len(first) == 64
    assert all(character in "0123456789abcdef" for character in first)
    assert path.read_text().strip() == first

    assert court.load_or_create_secret_key(str(path)) == first
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


def test_environment_variable_wins_without_touching_disk(tmp_path, monkeypatch):
    monkeypatch.setenv("COURT_SECRET_KEY", "e" * 64)
    path = tmp_path / ".court_secret"

    assert court.load_or_create_secret_key(str(path)) == "e" * 64
    assert not path.exists()


def test_waits_for_a_concurrent_writer_instead_of_truncating(tmp_path, monkeypatch):
    # Another process created the file but has not written its key yet.
    path = tmp_path / ".court_secret"
    path.write_text("")
    winner = "a" * 64
    reads = iter(["", "", "", winner])
    monkeypatch.setattr(court, "_read_key_file", lambda _path: next(reads, winner))
    monkeypatch.setattr(court.time, "sleep", lambda _seconds: None)

    assert court.load_or_create_secret_key(str(path)) == winner
    # The other process's file must be left alone, not overwritten.
    assert path.read_text() == ""


def test_short_existing_file_is_replaced(tmp_path, monkeypatch):
    path = tmp_path / ".court_secret"
    path.write_text("placeholder\n")
    monkeypatch.setattr(court.time, "sleep", lambda _seconds: None)

    key = court.load_or_create_secret_key(str(path))
    assert key != "placeholder"
    assert len(key) == 64
    assert path.read_text().strip() == key
