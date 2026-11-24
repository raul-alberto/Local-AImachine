"""Tests for running behind a trusted TLS-terminating reverse proxy.

The proxy speaks plain HTTP to Court, so Flask alone reports
http://127.0.0.1:5000 while the browser's Origin says https://court.example and
the login form was rejected as cross-origin. Forwarded headers repair that, but
only for peers named in COURT_TRUSTED_PROXIES, since a direct caller could
otherwise forge them and dodge the login throttle.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as court  # noqa: E402  (path bootstrap must run first)

PROXY = '10.0.0.5'
CLIENT = '203.0.113.7'
PUBLIC_ORIGIN = 'https://court.example'


@pytest.fixture(autouse=True)
def clean_throttle():
    court._login_failures.clear()
    yield
    court._login_failures.clear()


@pytest.fixture
def trusted_proxy(monkeypatch):
    monkeypatch.setattr(court, 'TRUSTED_PROXIES', frozenset({PROXY}))


def client_from(address):
    client = court.app.test_client()
    client.environ_base['REMOTE_ADDR'] = address
    return client


def signed_in_client(db, address=PROXY):
    client = client_from(address)
    with client.session_transaction() as session:
        session['logged_in'] = True
        session['session_version'] = 0
        session['username'] = db
        session['current_chat_index'] = -1
    return client


def proxy_headers(origin=PUBLIC_ORIGIN, extra=None):
    headers = {
        'Origin': origin,
        'X-Forwarded-Proto': 'https',
        'X-Forwarded-Host': 'court.example',
        'X-Forwarded-For': CLIENT,
    }
    headers.update(extra or {})
    return headers


def login(client, headers=None, password='password123', username='alice'):
    return client.post('/', data={'username': username, 'password': password}, headers=headers or {})


def test_https_origin_from_a_trusted_proxy_is_accepted(db, trusted_proxy):
    client = signed_in_client(db)

    response = client.post('/api/new_chat', headers=proxy_headers())

    assert response.status_code == 200
    assert [chat['title'] for chat in court.load_chats(db)] == ['New Chat']


def test_https_login_from_a_trusted_proxy_reaches_the_app(db, trusted_proxy):
    response = login(client_from(PROXY), headers=proxy_headers())

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/chat')


def test_forwarded_scheme_alone_is_enough_when_the_host_is_public(db, trusted_proxy):
    client = signed_in_client(db)

    proxied = client.post('/api/new_chat', headers={
        'Origin': 'https://localhost',
        'X-Forwarded-Proto': 'https',
        'X-Forwarded-For': CLIENT,
    })
    # Without the forwarded scheme Court still believes it is serving http,
    # which is exactly the 403 this fixes.
    unproxied = client.post('/api/new_chat', headers={'Origin': 'https://localhost'})

    assert proxied.status_code == 200
    assert unproxied.status_code == 403


def test_forwarded_headers_from_an_untrusted_peer_are_ignored(db):
    client = signed_in_client(db, address='198.51.100.9')

    response = client.post('/api/new_chat', headers=proxy_headers())

    assert response.status_code == 403


def test_a_trusted_proxy_does_not_vouch_for_a_foreign_origin(db, trusted_proxy):
    client = signed_in_client(db)

    response = client.post('/api/new_chat', headers=proxy_headers('https://evil.example'))

    assert response.status_code == 403


def test_client_supplied_forwarded_host_entries_are_ignored(db, trusted_proxy):
    client = signed_in_client(db)

    accepted = client.post('/api/new_chat', headers=proxy_headers(
        extra={'X-Forwarded-Host': 'evil.example, court.example'},
    ))
    rejected = client.post('/api/new_chat', headers=proxy_headers(
        extra={'X-Forwarded-Host': 'court.example, evil.example'},
    ))

    # The proxy appends its own value, so only the final entry counts.
    assert accepted.status_code == 200
    assert rejected.status_code == 403


def test_forwarded_port_completes_the_origin_authority(db, trusted_proxy):
    client = signed_in_client(db)

    response = client.post('/api/new_chat', headers=proxy_headers(
        'https://court.example:8443',
        {'X-Forwarded-Port': '8443'},
    ))

    assert response.status_code == 200


def test_default_forwarded_port_is_not_appended(db, trusted_proxy):
    client = signed_in_client(db)

    response = client.post('/api/new_chat', headers=proxy_headers(
        extra={'X-Forwarded-Port': '443'},
    ))

    assert response.status_code == 200


def test_login_throttle_keys_on_the_forwarded_client(db, trusted_proxy):
    for _ in range(court.LOGIN_MAX_ATTEMPTS):
        assert login(client_from(PROXY), headers=proxy_headers(), password='wrong').status_code == 200

    locked = login(client_from(PROXY), headers=proxy_headers())

    assert locked.status_code == 429
    assert court.login_lock_seconds(f'account:{CLIENT}:alice') > 0


def test_proxied_clients_are_throttled_separately(db, trusted_proxy):
    for index in range(court.LOGIN_ADDRESS_MAX_ATTEMPTS):
        login(
            client_from(PROXY),
            headers=proxy_headers(),
            password='wrong',
            username=f'user{index}',
        )
    assert login(client_from(PROXY), headers=proxy_headers()).status_code == 429

    allowed = login(
        client_from(PROXY),
        headers=proxy_headers(extra={'X-Forwarded-For': '198.51.100.20'}),
    )

    assert allowed.status_code == 302
    assert allowed.headers['Location'].endswith('/chat')


def test_client_supplied_forwarded_for_cannot_evade_the_throttle(db, trusted_proxy):
    for index in range(court.LOGIN_MAX_ATTEMPTS):
        login(
            client_from(PROXY),
            headers=proxy_headers(extra={'X-Forwarded-For': f'198.51.100.{index}, {CLIENT}'}),
            password='wrong',
        )

    assert court.login_lock_seconds(f'account:{CLIENT}:alice') > 0
    assert not any('198.51.100.' in key for key in court._login_failures)


def test_untrusted_peer_cannot_choose_its_throttle_address(db):
    for _ in range(court.LOGIN_MAX_ATTEMPTS):
        login(client_from('192.0.2.44'), headers={'X-Forwarded-For': '198.51.100.1'}, password='wrong')

    assert court.login_lock_seconds('account:192.0.2.44:alice') > 0
    assert not any('198.51.100.1' in key for key in court._login_failures)


def test_malformed_forwarded_address_falls_back_to_the_proxy_peer(db, trusted_proxy):
    login(client_from(PROXY), headers={'X-Forwarded-For': 'garbage'}, password='wrong')

    assert f'account:{PROXY}:alice' in court._login_failures


def test_parse_trusted_proxies_normalizes_the_allowlist():
    parsed = court.parse_trusted_proxies(' 127.0.0.1 , ::1,203.0.113.9 ,')

    assert parsed == frozenset({'127.0.0.1', '::1', '203.0.113.9'})


def test_parse_trusted_proxies_drops_malformed_entries(capsys):
    assert court.parse_trusted_proxies('127.0.0.1, not-an-ip') == frozenset({'127.0.0.1'})
    assert 'not-an-ip' in capsys.readouterr().out


def test_nothing_is_trusted_when_the_setting_is_absent():
    assert court.parse_trusted_proxies(None) == frozenset()
    assert court.parse_trusted_proxies('') == frozenset()
