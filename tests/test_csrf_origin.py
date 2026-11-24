"""Tests for the same-origin guard on state-changing requests.

SameSite=Lax already blocks plain cross-site form posts, but a page that
rebinds its hostname to 127.0.0.1 is same-site from the browser's view. The
Origin header still names the attacker's site, so writes are checked against it.
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
    court.init_user_db()
    court.create_user('alice', 'password123', 'Alice')
    return 'alice'


def signed_in_client(username):
    client = court.app.test_client()
    with client.session_transaction() as session:
        session['logged_in'] = True
        session['username'] = username
        session['current_chat_index'] = -1
    return client


def test_cross_origin_write_is_rejected(db):
    client = signed_in_client(db)

    response = client.post('/api/new_chat', headers={'Origin': 'http://evil.example'})

    assert response.status_code == 403
    assert court.load_chats(db) == []


def test_foreign_port_counts_as_cross_origin(db):
    client = signed_in_client(db)

    response = client.post('/api/new_chat', headers={'Origin': 'http://localhost:9999'})

    assert response.status_code == 403
    assert court.load_chats(db) == []


def test_null_origin_is_rejected(db):
    client = signed_in_client(db)

    response = client.post('/api/new_chat', headers={'Origin': 'null'})

    assert response.status_code == 403


def test_same_origin_write_still_works(db):
    client = signed_in_client(db)

    response = client.post(
        '/api/new_chat',
        headers={'Origin': 'http://localhost'},
    )

    assert response.status_code == 200
    assert [chat['title'] for chat in court.load_chats(db)] == ['New Chat']


def test_script_client_without_origin_still_works(db):
    client = signed_in_client(db)

    response = client.post('/api/new_chat')

    assert response.status_code == 200


def test_cross_origin_login_post_is_rejected(db):
    response = court.app.test_client().post(
        '/',
        data={'username': 'alice', 'password': 'password123'},
        headers={'Origin': 'http://evil.example'},
    )

    assert response.status_code == 403


def test_reads_are_not_blocked(db):
    client = signed_in_client(db)

    response = client.get('/chat', headers={'Origin': 'http://evil.example'})

    assert response.status_code == 200
