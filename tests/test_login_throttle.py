"""Tests for the persisted login and registration throttling.

The tally used to live in a module-level dict, so restarting Court, or running a
second worker, forgot every lock. These tests pin the new contract: rows live in
users.db, independent connections share one tally, expiry and pruning still
work, and registration is throttled per address as well.
"""

import sys
from concurrent.futures import ThreadPoolExecutor
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
    court.clear_all_login_failures()
    yield tmp_path
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


def login(client, password='password123', username='alice'):
    return client.post('/', data={'username': username, 'password': password})


def register(client, username, password='password123'):
    return client.post('/register', data={
        'username': username,
        'display_name': username,
        'password': password,
        'confirm_password': password,
    })


def test_failures_are_stored_in_users_db(db):
    for _ in range(court.LOGIN_MAX_ATTEMPTS):
        court.record_login_failure('account:127.0.0.1:alice')

    stored = throttle_rows()['account:127.0.0.1:alice']

    assert stored['count'] == court.LOGIN_MAX_ATTEMPTS
    assert stored['locked_until'] > court.time.time()
    # The old in-memory table is gone, so no lock can live only in this process.
    assert not hasattr(court, '_login_failures')


def test_a_lock_survives_a_fresh_process(db):
    for _ in range(court.LOGIN_MAX_ATTEMPTS):
        login(court.app.test_client(), password='wrong-password')

    # A new client shares no Python state with the one above, only users.db.
    restarted = court.app.test_client()
    response = login(restarted)

    assert response.status_code == 429
    assert b'Too many failed attempts' in response.data
    assert throttle_rows()['account:127.0.0.1:alice']['locked_until'] > court.time.time()


def test_independent_connections_share_one_tally(db):
    def record(_):
        court.record_login_failure('address:10.0.0.9')

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(record, range(12)))

    # Every increment landed: no read-modify-write was lost between connections.
    assert throttle_rows()['address:10.0.0.9']['count'] == 12


def test_both_the_account_and_the_address_keys_are_recorded(db):
    response = login(court.app.test_client(), password='wrong-password')

    assert response.status_code == 200
    stored = throttle_rows()
    assert stored['account:127.0.0.1:alice']['count'] == 1
    assert stored['address:127.0.0.1']['count'] == 1


def test_expired_lock_allows_sign_in(db):
    for _ in range(court.LOGIN_MAX_ATTEMPTS):
        login(court.app.test_client(), password='wrong-password')
    assert login(court.app.test_client()).status_code == 429

    conn = court._connect_user_db()
    try:
        with conn:
            conn.execute('UPDATE login_throttle SET locked_until = ?', (court.time.time() - 1.0,))
    finally:
        conn.close()

    allowed = login(court.app.test_client())

    assert allowed.status_code == 302
    assert allowed.headers['Location'].endswith('/chat')


def test_window_expiry_restarts_the_count(db):
    seed_throttle('address:10.1.1.1', 4, court.time.time() - court.LOGIN_WINDOW_SECONDS - 1, 0)

    court.record_login_failure('address:10.1.1.1')

    assert throttle_rows()['address:10.1.1.1']['count'] == 1


def test_pruning_drops_expired_rows_and_keeps_live_locks(db):
    now = court.time.time()
    seed_throttle('stale', 1, now - court.LOGIN_WINDOW_SECONDS - 5, 0)
    seed_throttle('live', 5, now - court.LOGIN_WINDOW_SECONDS - 5, now + 60)

    court.prune_login_failures(now)

    stored = throttle_rows()
    assert 'stale' not in stored
    assert 'live' in stored


def test_registration_is_throttled_per_address(db):
    client = court.app.test_client()

    for index in range(court.REGISTER_MAX_ATTEMPTS):
        assert register(client, f'user{index}').status_code == 302

    # A fresh client carries no queued "Account created" flash, so the 429 page
    # is the one that shows the throttle notice.
    blocked = register(court.app.test_client(), 'one-too-many')

    assert blocked.status_code == 429
    assert b'Too many registration attempts' in blocked.data
    assert court.get_user_by_username('one-too-many') is None


def test_registration_attempts_count_even_when_validation_fails(db):
    client = court.app.test_client()

    for _ in range(court.REGISTER_MAX_ATTEMPTS):
        # Username too short, so nothing is created but the attempt is spent.
        assert register(client, 'x', password='123').status_code == 200

    assert register(client, 'a-real-name').status_code == 429


def test_registration_throttle_is_per_address(db):
    noisy = court.app.test_client()
    noisy.environ_base['REMOTE_ADDR'] = '10.5.5.5'
    other = court.app.test_client()
    other.environ_base['REMOTE_ADDR'] = '10.6.6.6'

    for index in range(court.REGISTER_MAX_ATTEMPTS):
        register(noisy, f'noisy{index}')
    assert register(noisy, 'noisy-extra').status_code == 429

    assert register(other, 'quiet-one').status_code == 302


def test_registration_throttle_survives_a_restart(db):
    first = court.app.test_client()
    first.environ_base['REMOTE_ADDR'] = '10.7.7.7'
    for index in range(court.REGISTER_MAX_ATTEMPTS):
        register(first, f'fresh{index}')

    restarted = court.app.test_client()
    restarted.environ_base['REMOTE_ADDR'] = '10.7.7.7'

    assert register(restarted, 'after-restart').status_code == 429


def test_registration_throttle_uses_the_forwarded_client_address(db, monkeypatch):
    monkeypatch.setattr(court, 'TRUSTED_PROXIES', frozenset({'10.0.0.5'}))
    proxy = court.app.test_client()
    proxy.environ_base['REMOTE_ADDR'] = '10.0.0.5'

    def forwarded(address):
        return {'X-Forwarded-For': address}

    for index in range(court.REGISTER_MAX_ATTEMPTS):
        register_with = proxy.post(
            '/register',
            data={
                'username': f'proxied{index}',
                'display_name': f'proxied{index}',
                'password': 'password123',
                'confirm_password': 'password123',
            },
            headers=forwarded('203.0.113.9'),
        )
        assert register_with.status_code == 302

    blocked = proxy.post(
        '/register',
        data={
            'username': 'proxied-blocked',
            'display_name': 'proxied-blocked',
            'password': 'password123',
            'confirm_password': 'password123',
        },
        headers=forwarded('203.0.113.9'),
    )
    other_client = proxy.post(
        '/register',
        data={
            'username': 'proxied-ok',
            'display_name': 'proxied-ok',
            'password': 'password123',
            'confirm_password': 'password123',
        },
        headers=forwarded('203.0.113.10'),
    )

    assert blocked.status_code == 429
    assert other_client.status_code == 302
