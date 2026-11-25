"""Tests for server-side session revocation.

A signed cookie is otherwise valid until it expires, so a stolen one survives a
password change. Each user carries a session_version that the cookie must match;
changing the password bumps it, evicting every other session.
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


def signed_in(password='password123'):
    client = court.app.test_client()
    response = client.post('/', data={'username': 'alice', 'password': password})
    assert response.status_code == 302
    return client


def change_password(client, current='password123', new='brand-new-password'):
    return client.post('/account/password', data={
        'current_password': current,
        'new_password': new,
        'confirm_password': new,
    })


def test_password_change_evicts_other_sessions_but_keeps_the_current_one(db):
    changing = signed_in()
    stolen = signed_in()
    assert stolen.get('/chat').status_code == 200

    assert change_password(changing).status_code == 302

    assert changing.get('/chat').status_code == 200
    evicted = stolen.get('/chat')
    assert evicted.status_code == 302
    assert evicted.headers['Location'].endswith('/')


def test_evicted_session_gets_401_on_api_calls(db):
    changing = signed_in()
    stolen = signed_in()
    change_password(changing)

    response = stolen.post('/api/new_chat')

    assert response.status_code == 401
    assert response.get_json()['error'] == 'Session expired'


def test_password_change_bumps_the_stored_version(db):
    before = court.get_user_by_username('alice')['session_version']

    assert court.update_user_password('alice', 'brand-new-password') == before + 1
    assert court.get_user_by_username('alice')['session_version'] == before + 1


def test_sign_in_records_the_current_version(db):
    client = signed_in()

    with client.session_transaction() as session:
        assert session['session_version'] == court.get_user_by_username('alice')['session_version']


def test_cookie_without_a_version_is_rejected(db):
    client = court.app.test_client()
    with client.session_transaction() as session:
        session['logged_in'] = True
        session['username'] = 'alice'

    response = client.get('/chat')

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/')


def test_static_assets_still_render_for_a_stale_cookie(db):
    client = court.app.test_client()
    with client.session_transaction() as session:
        session['logged_in'] = True
        session['username'] = 'alice'

    assert client.get('/static/style.css').status_code == 200
