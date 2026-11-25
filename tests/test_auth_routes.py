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
def clean_throttle(db):
    court.clear_all_login_failures()
    yield
    court.clear_all_login_failures()


def throttle_rows():
    conn = court._connect_user_db()
    try:
        return {
            row['key']: dict(row)
            for row in conn.execute('SELECT key, count, first_seen, locked_until FROM login_throttle')
        }
    finally:
        conn.close()


def seed_throttle(key, count, first_seen, locked_until):
    conn = court._connect_user_db()
    try:
        with conn:
            conn.execute(
                'INSERT OR REPLACE INTO login_throttle (key, count, first_seen, locked_until) '
                'VALUES (?, ?, ?, ?)',
                (key, count, first_seen, locked_until),
            )
    finally:
        conn.close()


def expire_locks(key_pattern='%'):
    conn = court._connect_user_db()
    try:
        with conn:
            conn.execute(
                'UPDATE login_throttle SET locked_until = ? WHERE key LIKE ?',
                (court.time.time() - 1.0, key_pattern),
            )
    finally:
        conn.close()


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


def test_first_registration_unblocks_the_login_page(db):
    client = court.app.test_client()
    assert client.get('/').status_code == 302  # no accounts yet: go register

    created = client.post('/register', data={
        'username': 'alice',
        'display_name': 'Alice',
        'password': 'correct-horse',
        'confirm_password': 'correct-horse',
    })

    assert created.status_code == 302
    assert created.headers['Location'].endswith('/')
    assert client.get('/').status_code == 200  # login form, not another redirect

    signed_in = login(client, 'correct-horse')
    assert signed_in.status_code == 302
    assert signed_in.headers['Location'].endswith('/chat')


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
    expire_locks()

    unlocked = login(client, 'correct-horse')

    assert unlocked.status_code == 302
    assert unlocked.headers['Location'].endswith('/chat')


def test_stale_throttle_entries_are_pruned_but_live_locks_survive(db):
    now = court.time.time()
    window = court.LOGIN_WINDOW_SECONDS
    seed_throttle('old:alice', 2, now - window - 1, 0)
    seed_throttle('recent:bob', 1, now, 0)
    seed_throttle('locked:carol', 5, now - window - 1, now + 60)

    court.record_login_failure('new:dave')

    rows = throttle_rows()
    assert 'old:alice' not in rows
    assert 'recent:bob' in rows
    # A lock that outlasted its counting window must still be enforced.
    assert 'locked:carol' in rows
    assert court.login_lock_seconds('locked:carol') > 0
    assert rows['new:dave']['count'] == 1


def test_successful_login_clears_only_the_account_counter(db):
    make_user()
    client = court.app.test_client()

    for _ in range(3):
        login(client, 'wrong-password')
    assert throttle_rows()

    response = login(client, 'correct-horse')

    assert response.status_code == 302
    rows = throttle_rows()
    assert not any(key.startswith('account:') for key in rows)
    # The address tally survives, so one valid login cannot flush a spray.
    address_entry = next(
        entry for key, entry in rows.items() if key.startswith('address:')
    )
    assert address_entry['count'] == 3


def test_cycling_usernames_hits_the_address_limit(db):
    make_user()
    client = court.app.test_client()

    for index in range(court.LOGIN_ADDRESS_MAX_ATTEMPTS):
        response = login(client, 'wrong-password', username=f'user{index}')
        assert response.status_code == 200

    blocked = login(client, 'correct-horse')

    assert blocked.status_code == 429
    assert b'Too many failed attempts' in blocked.data
    # No single account got close to its own limit; the address tally did it.
    account_counts = [
        entry['count'] for key, entry in throttle_rows().items()
        if key.startswith('account:')
    ]
    assert max(account_counts) == 1


def test_address_limit_is_per_address(db):
    make_user()
    noisy = court.app.test_client()
    noisy.environ_base['REMOTE_ADDR'] = '10.1.2.3'
    other = court.app.test_client()
    other.environ_base['REMOTE_ADDR'] = '10.9.9.9'

    for index in range(court.LOGIN_ADDRESS_MAX_ATTEMPTS):
        login(noisy, 'wrong-password', username=f'user{index}')
    assert login(noisy, 'correct-horse').status_code == 429

    allowed = login(other, 'correct-horse')
    assert allowed.status_code == 302
    assert allowed.headers['Location'].endswith('/chat')


def test_address_lock_expires(db):
    make_user()
    client = court.app.test_client()

    for index in range(court.LOGIN_ADDRESS_MAX_ATTEMPTS):
        login(client, 'wrong-password', username=f'user{index}')
    assert login(client, 'correct-horse').status_code == 429

    expire_locks('address:%')

    allowed = login(client, 'correct-horse')
    assert allowed.status_code == 302
