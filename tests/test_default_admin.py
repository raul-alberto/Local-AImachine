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


def test_login_page_warns_while_the_default_password_is_live(db):
    court.create_user('admin', 'admin123', 'Admin')

    page = client().get('/')

    assert page.status_code == 200
    assert b'published password' in page.data


def test_login_page_warning_goes_away_after_the_change(db):
    court.create_user('admin', 'admin123', 'Admin')
    court.update_user_password('admin', 'a-much-better-password')

    page = client().get('/')

    assert b'published password' not in page.data


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
