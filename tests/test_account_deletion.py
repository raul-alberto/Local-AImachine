"""Tests for password-confirmed account deletion.

Deleting an account removes the user row plus everything keyed to it: chats,
RAG documents, and the settings entry in storage.json. Another account on the
same install keeps all of its data, and a session still open for the deleted
account stops working immediately.
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
    court.create_user('bob', 'password123', 'Bob')
    seed_account('alice')
    seed_account('bob')
    court.clear_all_login_failures()
    return tmp_path


def seed_account(username):
    mark = f'{username}-secret'
    court.save_chats(username, [{
        'title': f'{username} chat',
        'messages': [{'type': 'ai', 'message': f'<p>{mark}</p>', 'sources': []}],
        'tags': [f'{username}-tag'],
    }])
    court.save_user_rag(username, {
        'enabled': True,
        'documents': [{
            'id': f'{username}-doc',
            'name': f'{username}.txt',
            'uploaded_at': '2026-01-01T00:00:00',
            'chunks': [{'text': mark, 'embedding': None}],
        }],
    })
    court.save_user_settings(
        username,
        f'{username} prompt',
        court.DEFAULT_GENERATION_SETTINGS,
        {'assistant_name': 'Court', 'creator_name': 'Nox', 'theme': 'crimson'},
    )


def signed_in(username):
    client = court.app.test_client()
    with client.session_transaction() as session:
        session['logged_in'] = True
        session['session_version'] = 0
        session['username'] = username
        session['display_name'] = username.title()
        session['current_chat_index'] = 0
    return client


def delete_account(client, password='password123'):
    return client.post('/account/delete', data={'password': password})


def test_deletion_page_asks_for_confirmation(db):
    response = signed_in('alice').get('/account/delete')

    assert response.status_code == 200
    assert b'Delete account' in response.data
    assert b'alice' in response.data


def test_deletion_requires_the_current_password(db):
    client = signed_in('alice')

    response = delete_account(client, password='wrong-password')

    assert response.status_code == 400
    assert b'Nothing was deleted' in response.data
    assert court.get_user_by_username('alice') is not None
    assert [chat['title'] for chat in court.load_chats('alice')] == ['alice chat']
    assert [doc['id'] for doc in court.get_user_rag('alice')['documents']] == ['alice-doc']
    with client.session_transaction() as session:
        assert session.get('logged_in') is True


def test_deletion_removes_the_account_with_its_data(db):
    client = signed_in('alice')

    response = delete_account(client)

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/')
    assert court.get_user_by_username('alice') is None
    assert court.load_chats('alice') == []
    assert court.get_user_rag('alice')['documents'] == []
    assert 'alice' not in court.load_rag_store().get('users', {})
    assert 'alice' not in court.load_storage().get('users', {})
    with client.session_transaction() as session:
        assert not session.get('logged_in')


def test_deleted_account_cannot_sign_in_again(db):
    delete_account(signed_in('alice'))

    response = court.app.test_client().post(
        '/', data={'username': 'alice', 'password': 'password123'},
    )

    assert response.status_code == 200
    assert b'Invalid credentials' in response.data


def test_the_other_account_keeps_all_of_its_data(db):
    delete_account(signed_in('alice'))

    assert court.get_user_by_username('bob') is not None
    assert [chat['title'] for chat in court.load_chats('bob')] == ['bob chat']
    assert [doc['id'] for doc in court.get_user_rag('bob')['documents']] == ['bob-doc']
    assert court.load_storage()['users']['bob']['system_prompt'] == 'bob prompt'
    assert court.load_rag_store()['users']['bob']['documents'][0]['id'] == 'bob-doc'


def test_the_other_account_can_still_sign_in(db):
    delete_account(signed_in('alice'))

    response = court.app.test_client().post(
        '/', data={'username': 'bob', 'password': 'password123'},
    )

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/chat')


def test_a_session_open_for_the_deleted_account_is_revoked(db):
    deleted = signed_in('alice')
    open_elsewhere = signed_in('alice')

    delete_account(deleted)
    response = open_elsewhere.get('/chat')

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/')


@pytest.mark.parametrize('method', ['get', 'post'])
def test_deletion_requires_sign_in(db, method):
    response = getattr(court.app.test_client(), method)(
        '/account/delete', data={'password': 'password123'},
    )

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/')
    assert court.get_user_by_username('alice') is not None


def test_deleting_the_last_account_returns_to_registration(db):
    court.delete_user('bob')

    delete_account(signed_in('alice'))

    assert not court.has_any_user()
    page = court.app.test_client().get('/')
    assert page.status_code == 302
    assert page.headers['Location'].endswith('/register')
