"""Every chats payload the browser can render must be sanitized server-side.

AI replies are stored raw (the model produced them), and the browser assigns
them to innerHTML after Markdown rendering. A payload that skips the sanitizer
would reopen the XSS hole the reply sanitizer closed, so each endpoint that
returns chats is checked with a hostile stored message.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as court  # noqa: E402  (path bootstrap must run first)

RAW = 'hello <img src=x onerror="alert(1)"><script>alert(2)</script> <b>bold</b>'


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(court, 'USER_DB_FILE', str(tmp_path / 'users.db'))
    monkeypatch.setattr(court, 'DATA_FILE', str(tmp_path / 'storage.json'))
    monkeypatch.setattr(court, 'RAG_FILE', str(tmp_path / 'rag_store.json'))
    court.init_user_db()
    court.create_user('alice', 'password123', 'Alice')
    chat = {'title': 'Raw', 'tags': [], 'messages': [{'type': 'ai', 'message': RAW, 'sources': []}]}
    court.save_chats('alice', [dict(chat), dict(chat)])
    return 'alice'


def signed_in(index=0):
    client = court.app.test_client()
    with client.session_transaction() as session:
        session['logged_in'] = True
        session['session_version'] = 0
        session['username'] = 'alice'
        session['current_chat_index'] = index
    return client


def assert_clean(message):
    assert 'onerror' not in message
    assert '<script' not in message
    assert 'alert(2)' not in message or '&lt;script' in message
    assert 'hello' in message
    assert 'bold' in message


def test_stored_replies_stay_raw_for_prompts(db):
    assert court.load_chats('alice')[0]['messages'][0]['message'] == RAW


def test_delete_chat_response_is_sanitized(db):
    payload = signed_in(index=1).post('/api/delete_chat/1').get_json()

    assert_clean(payload['chats'][0]['messages'][0]['message'])


def test_rename_chat_response_is_sanitized(db):
    payload = signed_in().post('/api/rename_chat/0', json={'title': 'Renamed'}).get_json()

    assert_clean(payload['chats'][0]['messages'][0]['message'])


def test_tag_responses_are_sanitized(db):
    client = signed_in()
    added = client.post('/api/add_tag/0', json={'tag': 'work'}).get_json()
    removed = client.post('/api/remove_tag/0', json={'tag': 'work'}).get_json()

    assert_clean(added['chats'][0]['messages'][0]['message'])
    assert_clean(removed['chats'][0]['messages'][0]['message'])


def test_load_chat_and_full_export_are_sanitized(db):
    loaded = signed_in().post('/api/load_chat/0').get_json()
    exported = signed_in().get('/api/chats?full=1').get_json()

    assert_clean(loaded['chat']['messages'][0]['message'])
    assert_clean(exported['chats'][0]['messages'][0]['message'])


def test_chat_page_does_not_emit_the_hostile_markup(db):
    page = signed_in().get('/chat').get_data(as_text=True)

    assert 'onerror' not in page
    assert '<script>alert(2)</script>' not in page
