"""Errors from the model must stay plain text on the way back.

The live stream renders error packets with textContent, so storing them as AI
messages would make the same text go through the Markdown/HTML branch on
reload. They are stored with type 'error', which the page renders as text.
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
    return 'alice'


def signed_in():
    client = court.app.test_client()
    with client.session_transaction() as session:
        session['logged_in'] = True
        session['session_version'] = 0
        session['username'] = 'alice'
        session['current_chat_index'] = 0
    return client


def fail_requests(monkeypatch):
    def boom(*args, **kwargs):
        raise court.requests.exceptions.ConnectionError('connection refused')

    monkeypatch.setattr(court.requests, 'post', boom)


def last_message():
    return court.load_chats('alice')[0]['messages'][-1]


def test_non_stream_failure_is_stored_as_an_error(db, monkeypatch):
    fail_requests(monkeypatch)

    response = signed_in().post('/api/chat', json={'message': 'hello'})

    assert response.status_code == 200
    stored = last_message()
    assert stored['type'] == 'error'
    assert stored['message'].startswith('Error: AI request failed')


def test_stream_failure_is_stored_as_an_error(db, monkeypatch):
    fail_requests(monkeypatch)

    response = signed_in().post('/api/chat_stream', json={'message': 'hello'})

    packets = [court.json.loads(line) for line in response.get_data(as_text=True).splitlines() if line]
    assert [packet['type'] for packet in packets if packet['type'] == 'error'] == ['error']
    stored = last_message()
    assert stored['type'] == 'error'
    assert stored['message'].startswith('Error: AI request failed')


def test_stored_error_text_is_not_treated_as_markdown(db):
    hostile = 'Error: <img src=x onerror=alert(1)> while streaming'
    court.save_chats('alice', [{
        'title': 'Failed',
        'tags': [],
        'messages': [{'type': 'error', 'message': hostile, 'sources': []}],
    }])

    loaded = signed_in().post('/api/load_chat/0').get_json()['chat']['messages'][0]

    # The sanitizer must not rewrite it: the client renders it with textContent,
    # so the stored text is returned exactly as written.
    assert loaded['type'] == 'error'
    assert loaded['message'] == hostile


def test_chat_js_only_opts_ai_messages_into_html():
    template = (Path(__file__).resolve().parent.parent / 'templates' / 'chat.html').read_text()

    assert "appendMessage(msg.message, msg.type, msg.sources || [], msg.type === 'ai')" in template
    assert "const fromAi = type !== 'user';" in template
    assert "appendMessage(packet.message || 'Error: Unable to get response', 'ai');" in template
