"""Tests for the launcher's hand-off to app.main().

The launcher must start the app exactly once, and the CLI flags it receives
(from run-local.bat's %*) must reach the server settings.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as court  # noqa: E402  (path bootstrap must run first)
import launcher  # noqa: E402


def test_launcher_starts_the_app_once(monkeypatch):
    monkeypatch.setattr(launcher, 'is_port_open', lambda host, port, timeout=1.0: True)
    monkeypatch.setattr(launcher, 'is_model_installed', lambda: True)
    starts = []
    monkeypatch.setattr(launcher.app, 'main', lambda: starts.append('started'))

    launcher.main()

    assert starts == ['started']


def test_lan_and_port_flags_reach_the_server(monkeypatch):
    started = {}
    monkeypatch.setattr(court, 'init_user_db', lambda: None)
    monkeypatch.setattr(court, 'uses_default_admin_password', lambda: False)
    monkeypatch.setattr(court.app, 'run', lambda **kwargs: started.update(kwargs))
    monkeypatch.setattr(sys, 'argv', ['launcher.py', '--lan', '--port', '8123'])

    court.main()

    assert started == {'host': '0.0.0.0', 'port': 8123}


def test_fresh_install_starts_without_a_seeded_admin(tmp_path, monkeypatch):
    monkeypatch.setattr(court, 'USER_DB_FILE', str(tmp_path / 'users.db'))
    monkeypatch.setattr(court, 'DATA_FILE', str(tmp_path / 'storage.json'))
    started = {}
    monkeypatch.setattr(court.app, 'run', lambda **kwargs: started.update(kwargs))
    monkeypatch.setattr(sys, 'argv', ['app.py'])

    court.main()

    assert started == {'host': '127.0.0.1', 'port': 5000}
    assert not court.has_any_user()
    assert court.uses_default_admin_password() is False


def test_flags_default_to_loopback(monkeypatch):
    started = {}
    monkeypatch.delenv('COURT_HOST', raising=False)
    monkeypatch.delenv('COURT_PORT', raising=False)
    monkeypatch.setattr(court, 'init_user_db', lambda: None)
    monkeypatch.setattr(court, 'uses_default_admin_password', lambda: False)
    monkeypatch.setattr(court.app, 'run', lambda **kwargs: started.update(kwargs))
    monkeypatch.setattr(sys, 'argv', ['launcher.py'])

    court.main()

    assert started == {'host': '127.0.0.1', 'port': 5000}
