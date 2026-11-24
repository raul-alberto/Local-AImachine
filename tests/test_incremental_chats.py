"""Tests for incremental chat persistence and lazy chat loading.

Saving a turn must touch only the chat that changed, and /chat must not ship
every stored chat's messages to the browser.
"""

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as court  # noqa: E402  (path bootstrap must run first)


def make_chat(title, text):
    return {
        'title': title,
        'messages': [{'type': 'user', 'message': text, 'sources': []}],
        'tags': [],
    }


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(court, 'USER_DB_FILE', str(tmp_path / 'users.db'))
    monkeypatch.setattr(court, 'DATA_FILE', str(tmp_path / 'storage.json'))
    court.init_user_db()
    court.create_user('alice', 'password123', 'Alice')
    return 'alice'


def signed_in(index=0):
    client = court.app.test_client()
    with client.session_transaction() as session:
        session['logged_in'] = True
        session['session_version'] = 0
        session['username'] = 'alice'
        session['current_chat_index'] = index
    return client


def count_writes():
    conn = sqlite3.connect(court.USER_DB_FILE)
    try:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS write_log (kind TEXT);
            CREATE TRIGGER IF NOT EXISTS chats_insert AFTER INSERT ON chats
                BEGIN INSERT INTO write_log VALUES ('insert'); END;
            CREATE TRIGGER IF NOT EXISTS chats_delete AFTER DELETE ON chats
                BEGIN INSERT INTO write_log VALUES ('delete'); END;
        ''')
        conn.commit()
    finally:
        conn.close()


def write_counts():
    conn = sqlite3.connect(court.USER_DB_FILE)
    try:
        return dict(conn.execute('SELECT kind, COUNT(*) FROM write_log GROUP BY kind'))
    finally:
        conn.close()


def test_saving_a_turn_writes_only_the_changed_chat(db):
    court.save_chats('alice', [make_chat('Alpha', 'first'), make_chat('Beta', 'second')])
    count_writes()

    chats = court.load_chats('alice')
    chats[0]['messages'].append({'type': 'ai', 'message': 'reply', 'sources': []})
    court.save_chats('alice', chats)

    # INSERT OR REPLACE rewrites one row; a table rewrite would insert both chats.
    assert write_counts() == {'insert': 1}
    assert court.load_chats('alice')[0]['messages'][-1]['message'] == 'reply'


def test_saving_unchanged_chats_writes_nothing(db):
    court.save_chats('alice', [make_chat('Alpha', 'first'), make_chat('Beta', 'second')])
    count_writes()

    court.save_chats('alice', court.load_chats('alice'))

    assert write_counts() == {}


def test_dropping_the_last_chat_deletes_only_that_row(db):
    court.save_chats('alice', [make_chat('A', 'a'), make_chat('B', 'b'), make_chat('C', 'c')])
    count_writes()

    court.save_chats('alice', court.load_chats('alice')[:2])

    assert write_counts() == {'delete': 1}
    assert [chat['title'] for chat in court.load_chats('alice')] == ['A', 'B']


def test_removing_a_middle_chat_keeps_the_rest_in_order(db):
    court.save_chats('alice', [make_chat('A', 'a'), make_chat('B', 'b'), make_chat('C', 'c')])

    chats = court.load_chats('alice')
    del chats[1]
    court.save_chats('alice', chats)

    stored = court.load_chats('alice')
    assert [chat['title'] for chat in stored] == ['A', 'C']
    assert [chat['messages'][0]['message'] for chat in stored] == ['a', 'c']


def test_chat_page_serialises_only_the_open_chat(db):
    court.save_chats('alice', [make_chat('Alpha', 'alpha-body'), make_chat('Beta', 'beta-body')])

    page = signed_in(index=0).get('/chat').get_data(as_text=True)

    assert 'Alpha' in page and 'Beta' in page  # sidebar still lists both
    assert 'alpha-body' in page
    assert 'beta-body' not in page


def test_chat_list_api_returns_summaries_without_messages(db):
    court.save_chats('alice', [make_chat('Alpha', 'alpha-body'), make_chat('Beta', 'beta-body')])

    payload = signed_in(index=1).get('/api/chats').get_json()

    assert payload['current_index'] == 1
    assert [(chat['title'], chat['message_count']) for chat in payload['chats']] == [
        ('Alpha', 1), ('Beta', 1),
    ]
    assert all('messages' not in chat for chat in payload['chats'])


def test_chat_list_api_can_return_full_chats_for_export(db):
    court.save_chats('alice', [make_chat('Alpha', 'alpha-body'), make_chat('Beta', 'beta-body')])

    payload = signed_in().get('/api/chats?full=1').get_json()

    assert [chat['messages'][0]['message'] for chat in payload['chats']] == [
        'alpha-body', 'beta-body',
    ]


def test_load_chat_returns_the_selected_chat_and_records_it(db):
    court.save_chats('alice', [make_chat('Alpha', 'alpha-body'), make_chat('Beta', 'beta-body')])
    client = signed_in(index=0)

    payload = client.post('/api/load_chat/1').get_json()

    assert payload['chat']['title'] == 'Beta'
    assert payload['chat']['messages'][0]['message'] == 'beta-body'
    with client.session_transaction() as session:
        assert session['current_chat_index'] == 1
