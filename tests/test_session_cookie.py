"""Tests for the session cookie hardening settings.

The session cookie carries the whole chat state, so it must not be readable by
page script (HttpOnly), must not ride along on cross-site form posts
(SameSite=Lax), and must expire after a bounded time rather than living forever.
"""

import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as court  # noqa: E402  (path bootstrap must run first)


def test_configures_strict_cookie_defaults():
    assert court.app.config['SESSION_COOKIE_HTTPONLY'] is True
    assert court.app.config['SESSION_COOKIE_SAMESITE'] == 'Lax'
    assert court.app.config['PERMANENT_SESSION_LIFETIME'] == timedelta(days=7)


def test_issued_session_cookie_carries_the_flags(tmp_path, monkeypatch):
    monkeypatch.setattr(court, 'USER_DB_FILE', str(tmp_path / 'users.db'))
    monkeypatch.setattr(court, 'DATA_FILE', str(tmp_path / 'storage.json'))
    court.init_user_db()
    court.create_user('cookie-test', 'password123', 'Cookie Test')

    client = court.app.test_client()
    with client.session_transaction() as session:
        session['logged_in'] = True
        session['session_version'] = 0
        session['username'] = 'cookie-test'
        session.permanent = True

    response = client.get('/chat')
    assert response.status_code == 200

    cookie = response.headers.get('Set-Cookie', '')
    assert 'session=' in cookie
    assert 'HttpOnly' in cookie
    assert 'SameSite=Lax' in cookie
    # A permanent session must carry an expiry; a browser-session cookie would not.
    assert 'Expires=' in cookie
