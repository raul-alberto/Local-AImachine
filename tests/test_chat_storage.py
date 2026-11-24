"""Tests for server-side chat storage.

Chats used to travel in the Flask session cookie, which overflowed around 4 KB
of conversation and resent every message on every request. These lock in that
they now live in SQLite per user and are readable from a fresh client.
"""

import json
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


def chat(title, message='hello', tags=None):
    return {
        'title': title,
        'messages': [{'type': 'user', 'message': message, 'sources': []}],
        'tags': tags or [],
    }


def test_save_then_load_round_trips_every_field(db):
    chats = [
        chat('First', 'hello there', ['one', 'two']),
        {'title': 'Second', 'messages': [
            {'type': 'user', 'message': 'question', 'sources': []},
            {'type': 'ai', 'message': '<p>answer</p>', 'sources': [{'id': 1, 'source': 'doc.txt', 'snippet': 'x', 'score': 0.5}]},
        ], 'tags': []},
    ]

    court.save_chats(db, chats)

    assert court.load_chats(db) == chats


def test_save_replaces_instead_of_appending(db):
    court.save_chats(db, [chat('Old')])
    court.save_chats(db, [chat('New')])

    assert [c['title'] for c in court.load_chats(db)] == ['New']


def test_deleting_every_chat_leaves_nothing_to_reload(db):
    court.save_chats(db, [chat('Gone')])
    court.delete_chats(db)

    assert court.load_chats(db) == []


def test_chats_are_scoped_to_their_user(db):
    court.create_user('bob', 'password123', 'Bob')
    court.save_chats(db, [chat('Alice only')])

    assert court.load_chats('bob') == []


def test_unknown_user_has_no_chats(db):
    assert court.load_chats('nobody') == []


def test_legacy_storage_json_chats_are_imported_once(db):
    legacy = {'users': {'alice': {
        'saved_chats': [chat('From storage.json')],
        'saved_current_chat_index': 0,
    }}}
    Path(court.DATA_FILE).write_text(json.dumps(legacy))

    assert court.load_chats(db) == []  # reading alone never imports
    court.migrate_legacy_chats(db)
    assert [c['title'] for c in court.load_chats(db)] == ['From storage.json']

    # The legacy copy is consumed, so a later delete is not undone by a re-import.
    court.delete_chats(db)
    court.migrate_legacy_chats(db)
    assert court.load_chats(db) == []


def test_persistent_login_imports_legacy_chats(db):
    legacy = {'users': {'alice': {
        'privacy_mode': 'persistent',
        'saved_chats': [chat('From an older version')],
    }}}
    Path(court.DATA_FILE).write_text(json.dumps(legacy))

    response = court.app.test_client().post(
        '/', data={'username': 'alice', 'password': 'password123'},
    )

    assert response.status_code == 302
    assert [c['title'] for c in court.load_chats(db)] == ['From an older version']


def test_ephemeral_login_ignores_legacy_chats(db):
    legacy = {'users': {'alice': {
        'privacy_mode': 'ephemeral',
        'saved_chats': [chat('From an older version')],
    }}}
    Path(court.DATA_FILE).write_text(json.dumps(legacy))

    court.app.test_client().post('/', data={'username': 'alice', 'password': 'password123'})

    assert court.load_chats(db) == []


def test_chat_routes_keep_their_response_shape(db):
    client = court.app.test_client()
    with client.session_transaction() as session:
        session['logged_in'] = True
        session['username'] = db

    created = client.post('/api/new_chat')
    assert created.status_code == 200
    assert [c['title'] for c in created.get_json()['chats']] == ['New Chat']
    assert created.get_json()['current_index'] == 0

    renamed = client.post('/api/rename_chat/0', json={'title': 'Renamed'})
    assert renamed.get_json()['chats'][0]['title'] == 'Renamed'
    assert court.load_chats(db)[0]['title'] == 'Renamed'

    deleted = client.post('/api/delete_chat/0')
    assert deleted.get_json()['chats'] == []
    assert deleted.get_json()['current_index'] == -1
    assert court.load_chats(db) == []


def test_session_cookie_carries_no_chat_content(db):
    big_message = 'Z' * 500
    court.save_chats(db, [chat(f'Chat {index}', big_message) for index in range(20)])

    client = court.app.test_client()
    with client.session_transaction() as session:
        session['logged_in'] = True
        session['username'] = db
        session.permanent = True

    response = client.get('/chat')
    assert response.status_code == 200
    assert 'Chat 0' in response.get_data(as_text=True)

    cookie = response.headers.get('Set-Cookie', '')
    assert 'session=' in cookie
    assert len(cookie) < 1000  # the ~10 KB of chats must not be in here
