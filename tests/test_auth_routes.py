"""Route-level tests for login flow and throttling.

Covers the behaviour added with the loopback/no-default-admin work: an empty
install sends you to registration, repeated bad passwords lock sign-in, the
lock expires, and a good password resets the counter.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as court  # noqa: E402  (path bootstrap must run first)


@pytest.fixture(autouse=True)
def clean_throttle():
    court._login_failures.clear()
    yield
    court._login_failures.clear()


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(court, 'USER_DB_FILE', str(tmp_path / 'users.db'))
    monkeypatch.setattr(court, 'DATA_FILE', str(tmp_path / 'storage.json'))
    monkeypatch.setattr(court, 'RAG_FILE', str(tmp_path / 'rag_store.json'))
    court.init_user_db()
    return tmp_path


def make_user(password='correct-horse'):
    court.create_user('alice', password, 'Alice')


def login(client, password, username='alice'):
    return client.post('/', data={'username': username, 'password': password})


def test_empty_install_redirects_to_registration(db):
    client = court.app.test_client()

    page = client.get('/')
    assert page.status_code == 302
    assert page.headers['Location'].endswith('/register')

    submitted = client.post('/', data={'username': 'alice', 'password': 'anything'})
    assert submitted.status_code == 302
    assert submitted.headers['Location'].endswith('/register')


def test_five_failures_lock_the_next_attempt(db):
    make_user()
    client = court.app.test_client()

    for _ in range(court.LOGIN_MAX_ATTEMPTS):
        response = login(client, 'wrong-password')
        assert response.status_code == 200
        assert b'Invalid credentials' in response.data

    locked = login(client, 'wrong-password')
    assert locked.status_code == 429
    assert b'Too many failed attempts' in locked.data


def test_lockout_refuses_even_the_correct_password(db):
    make_user()
    client = court.app.test_client()

    for _ in range(court.LOGIN_MAX_ATTEMPTS):
        login(client, 'wrong-password')

    response = login(client, 'correct-horse')

    assert response.status_code == 429
    with client.session_transaction() as session:
        assert not session.get('logged_in')


def test_lock_expires_after_the_window(db):
    make_user()
    client = court.app.test_client()

    for _ in range(court.LOGIN_MAX_ATTEMPTS):
        login(client, 'wrong-password')
    assert login(client, 'correct-horse').status_code == 429

    # Let the lock elapse without waiting a real minute.
    for entry in court._login_failures.values():
        entry['locked_until'] = court.time.time() - 1

    unlocked = login(client, 'correct-horse')

    assert unlocked.status_code == 302
    assert unlocked.headers['Location'].endswith('/chat')


def test_successful_login_clears_the_failure_counter(db):
    make_user()
    client = court.app.test_client()

    for _ in range(3):
        login(client, 'wrong-password')
    assert court._login_failures

    response = login(client, 'correct-horse')

    assert response.status_code == 302
    assert court._login_failures == {}
