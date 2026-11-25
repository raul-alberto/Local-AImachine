"""Tests for resetting a forgotten password from the command line."""

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


def answers(*values):
    """Stand in for getpass, asserting the prompts happen in order."""
    queue = list(values)

    def fake_getpass(prompt=''):
        assert queue, f'unexpected prompt: {prompt}'
        return queue.pop(0)

    return fake_getpass


def test_reset_sets_the_new_password_and_ends_sessions(db, monkeypatch):
    before = court.get_user_by_username('alice')['session_version']
    monkeypatch.setattr(court.getpass, 'getpass', answers('brand-new-password', 'brand-new-password'))

    assert court.reset_user_password('alice') == 0

    updated = court.get_user_by_username('alice')
    assert court.check_password_hash(updated['password_hash'], 'brand-new-password')
    assert not court.check_password_hash(updated['password_hash'], 'password123')
    assert updated['session_version'] == before + 1


def test_mismatched_confirmation_leaves_the_password_alone(db, monkeypatch, capsys):
    monkeypatch.setattr(court.getpass, 'getpass', answers('brand-new-password', 'typo-password'))

    assert court.reset_user_password('alice') == 1

    assert 'do not match' in capsys.readouterr().err
    assert court.check_password_hash(
        court.get_user_by_username('alice')['password_hash'], 'password123',
    )


def test_too_short_password_is_rejected_before_confirmation(db, monkeypatch, capsys):
    monkeypatch.setattr(court.getpass, 'getpass', answers('short'))

    assert court.reset_user_password('alice') == 1

    assert 'at least 8 characters' in capsys.readouterr().err
    assert court.check_password_hash(
        court.get_user_by_username('alice')['password_hash'], 'password123',
    )


def test_unknown_account_is_reported_without_prompting(db, monkeypatch, capsys):
    monkeypatch.setattr(court.getpass, 'getpass', answers())

    assert court.reset_user_password('nobody') == 1

    assert 'No account named' in capsys.readouterr().err


def test_cli_flag_resets_and_exits(db, monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['app.py', '--reset-password', 'alice'])
    monkeypatch.setattr(court.getpass, 'getpass', answers('brand-new-password', 'brand-new-password'))

    with pytest.raises(SystemExit) as exit_info:
        court.main()

    assert exit_info.value.code == 0
    assert court.check_password_hash(
        court.get_user_by_username('alice')['password_hash'], 'brand-new-password',
    )


def test_cli_reset_signs_out_sessions_that_were_already_open(db, monkeypatch):
    signed_in = court.app.test_client()
    signed_in.post('/', data={'username': 'alice', 'password': 'password123'})
    assert signed_in.get('/chat').status_code == 200

    monkeypatch.setattr(court.getpass, 'getpass', answers('brand-new-password', 'brand-new-password'))
    assert court.reset_user_password('alice') == 0

    evicted = signed_in.get('/chat')
    assert evicted.status_code == 302
    assert evicted.headers['Location'].endswith('/')

    fresh = court.app.test_client()
    assert fresh.post('/', data={'username': 'alice', 'password': 'brand-new-password'}).status_code == 302


def test_resetting_the_default_admin_password_lifts_the_gate(db, monkeypatch):
    court.create_user('admin', 'admin123', 'Admin')
    assert court.uses_default_admin_password() is True
    monkeypatch.setattr(court.getpass, 'getpass', answers('a-much-better-password', 'a-much-better-password'))

    assert court.reset_user_password('admin') == 0

    assert court.uses_default_admin_password() is False
