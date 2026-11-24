"""Tests for the leftover default admin account and the password change flow.

Installs created before the seeded account was removed still accept the
published admin/admin123 login, so it must be flagged and replaceable.
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
    return 'db'


def client(username=None):
    test_client = court.app.test_client()
    if username:
        with test_client.session_transaction() as session:
            session['logged_in'] = True
            session['session_version'] = 0
            session['username'] = username
    return test_client


def test_detects_and_clears_the_default_admin_password(db):
    court.create_user('admin', 'admin123', 'Admin')
    assert court.uses_default_admin_password() is True

    court.update_user_password('admin', 'a-much-better-password')

    assert court.uses_default_admin_password() is False
    assert court.check_password_hash(
        court.get_user_by_username('admin')['password_hash'], 'a-much-better-password',
    )


def test_fresh_install_has_no_default_admin(db):
    assert court.uses_default_admin_password() is False
    court.create_user('alice', 'password123', 'Alice')
    assert court.uses_default_admin_password() is False


def test_signed_out_login_page_does_not_disclose_the_default_password(db):
    court.create_user('admin', 'admin123', 'Admin')

    page = client().get('/')

    assert page.status_code == 200
    assert b'published default password' not in page.data


def test_default_admin_is_sent_to_the_password_page(db):
    court.create_user('admin', 'admin123', 'Admin')

    response = client('admin').get('/chat')

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/account/password')


def test_password_page_is_reachable_for_that_admin(db):
    court.create_user('admin', 'admin123', 'Admin')

    page = client('admin').get('/account/password')

    assert page.status_code == 200
    assert b'Change password' in page.data


def test_redirect_stops_after_the_password_change(db):
    court.create_user('admin', 'admin123', 'Admin')
    court.update_user_password('admin', 'a-much-better-password')

    page = login('admin', 'a-much-better-password').get('/chat')

    assert page.status_code == 200


def test_other_users_are_not_redirected(db):
    court.create_user('admin', 'admin123', 'Admin')
    court.create_user('alice', 'password123', 'Alice')

    page = client('alice').get('/chat')

    assert page.status_code == 200


def test_default_password_check_is_cached_per_stored_hash(db, monkeypatch):
    court.create_user('admin', 'admin123', 'Admin')
    real_check = court.check_password_hash
    calls = []

    def counting_check(password_hash, password):
        calls.append(password)
        return real_check(password_hash, password)

    monkeypatch.setattr(court, 'check_password_hash', counting_check)

    assert court.uses_default_admin_password() is True
    assert court.uses_default_admin_password() is True
    assert len(calls) == 1

    court.update_user_password('admin', 'a-much-better-password')

    assert court.uses_default_admin_password() is False
    assert len(calls) == 2


def test_password_edited_outside_the_app_is_picked_up(db):
    court.create_user('admin', 'admin123', 'Admin')
    assert court.uses_default_admin_password() is True

    conn = court._connect_user_db()
    try:
        conn.execute(
            'UPDATE users SET password_hash = ? WHERE username = ?',
            (court.generate_password_hash('a-much-better-password'), 'admin'),
        )
        conn.commit()
    finally:
        conn.close()

    assert court.uses_default_admin_password() is False


def test_removing_the_admin_account_clears_the_warning(db):
    court.create_user('admin', 'admin123', 'Admin')
    assert court.uses_default_admin_password() is True

    conn = court._connect_user_db()
    try:
        conn.execute('DELETE FROM users WHERE username = ?', ('admin',))
        conn.commit()
    finally:
        conn.close()

    assert court.uses_default_admin_password() is False


def login(username, password):
    test_client = court.app.test_client()
    response = test_client.post('/', data={'username': username, 'password': password})
    assert response.status_code == 302
    return test_client


def test_changing_the_default_admin_password_signs_out_other_sessions(db):
    court.create_user('admin', 'admin123', 'Admin')
    changing = login('admin', 'admin123')
    stolen = login('admin', 'admin123')  # cookie captured while the default worked
    assert stolen.get('/account/password').status_code == 200  # session is live

    changed = changing.post('/account/password', data={
        'current_password': 'admin123',
        'new_password': 'a-much-better-password',
        'confirm_password': 'a-much-better-password',
    })

    assert changed.status_code == 302
    assert changing.get('/chat').status_code == 200  # the device that changed it stays
    evicted = stolen.get('/chat')
    assert evicted.status_code == 302
    assert evicted.headers['Location'].endswith('/')


def test_password_page_requires_sign_in(db):
    response = client().get('/account/password')

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/')


def test_changing_the_password_replaces_the_hash(db):
    court.create_user('alice', 'password123', 'Alice')
    old_hash = court.get_user_by_username('alice')['password_hash']

    response = client('alice').post('/account/password', data={
        'current_password': 'password123',
        'new_password': 'brand-new-password',
        'confirm_password': 'brand-new-password',
    })

    assert response.status_code == 302
    new_hash = court.get_user_by_username('alice')['password_hash']
    assert new_hash != old_hash
    assert court.check_password_hash(new_hash, 'brand-new-password')
    assert not court.check_password_hash(new_hash, 'password123')


def test_wrong_current_password_is_rejected(db):
    court.create_user('alice', 'password123', 'Alice')

    response = client('alice').post('/account/password', data={
        'current_password': 'not-my-password',
        'new_password': 'brand-new-password',
        'confirm_password': 'brand-new-password',
    })

    assert response.status_code == 200
    assert b'Current password is incorrect.' in response.data
    assert court.check_password_hash(
        court.get_user_by_username('alice')['password_hash'], 'password123',
    )


def test_short_or_mismatched_new_password_is_rejected(db):
    court.create_user('alice', 'password123', 'Alice')
    signed_in = client('alice')

    short = signed_in.post('/account/password', data={
        'current_password': 'password123',
        'new_password': 'short',
        'confirm_password': 'short',
    })
    assert b'at least 8 characters' in short.data

    mismatch = signed_in.post('/account/password', data={
        'current_password': 'password123',
        'new_password': 'brand-new-password',
        'confirm_password': 'brand-new-passwerd',
    })
    assert b'do not match' in mismatch.data
    assert court.check_password_hash(
        court.get_user_by_username('alice')['password_hash'], 'password123',
    )
