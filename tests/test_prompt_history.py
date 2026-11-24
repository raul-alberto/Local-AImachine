"""Tests for conversation history in the model prompt.

Follow-up questions only work if prior turns reach the model, but the prompt is
still bounded: history is trimmed oldest-first, and the RAG context block must
survive alongside it.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as court  # noqa: E402  (path bootstrap must run first)

USER_TURN = {'type': 'user', 'message': 'What is a closure?', 'sources': []}
AI_TURN = {'type': 'ai', 'message': '<p>A closure captures its scope.</p>', 'sources': []}


class FakeResponse:
    def __init__(self, text='reply'):
        self.text = text

    def raise_for_status(self):
        pass

    def json(self):
        return {'response': self.text}

    def iter_lines(self, decode_unicode=False):
        yield json.dumps({'response': self.text})


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(court, 'USER_DB_FILE', str(tmp_path / 'users.db'))
    monkeypatch.setattr(court, 'DATA_FILE', str(tmp_path / 'storage.json'))
    court.init_user_db()
    court.create_user('alice', 'password123', 'Alice')
    court.save_chats('alice', [{'title': 'Talk', 'messages': [USER_TURN, AI_TURN], 'tags': []}])
    return 'alice'


def signed_in_client(username):
    client = court.app.test_client()
    with client.session_transaction() as session:
        session['logged_in'] = True
        session['username'] = username
        session['current_chat_index'] = 0
    return client


def stub_model(monkeypatch, sink):
    def fake_post(url, json=None, **kwargs):
        sink['prompt'] = json['prompt']
        return FakeResponse()

    monkeypatch.setattr(court.requests, 'post', fake_post)


def test_history_is_oldest_first_and_plain_text():
    history = court.format_history_for_prompt([USER_TURN, AI_TURN])

    assert history == 'User: What is a closure?\nAssistant: A closure captures its scope.'


def test_history_drops_the_oldest_turns_that_do_not_fit():
    messages = [
        {'type': 'user', 'message': 'ancient ' * 200, 'sources': []},
        {'type': 'ai', 'message': 'older answer', 'sources': []},
        {'type': 'user', 'message': 'newest question', 'sources': []},
    ]

    history = court.format_history_for_prompt(messages, token_budget=10)

    assert history.endswith('User: newest question')
    assert 'older answer' not in history
    assert 'ancient' not in history


def test_prompt_keeps_rag_block_alongside_history():
    prompt = court.build_chat_prompt(
        'You are Court.', 'User: hi\nAssistant: hello', 'and now?', '[1] notes.txt: context',
    )

    assert prompt.startswith('System: You are Court.')
    assert 'Local Context:\n[1] notes.txt: context' in prompt
    assert 'Conversation so far:\nUser: hi\nAssistant: hello' in prompt
    assert prompt.rstrip().endswith('Assistant:')


def test_prompt_without_history_or_rag_is_unchanged():
    prompt = court.build_chat_prompt('You are Court.', '', 'hello')

    assert 'Conversation so far' not in prompt
    assert 'Local Context' not in prompt
    assert prompt == 'System: You are Court.\n\nUser: hello\n\nAssistant:'


def test_chat_endpoint_sends_prior_turns_and_rag(monkeypatch, db):
    sent = {}
    stub_model(monkeypatch, sent)
    monkeypatch.setattr(
        court, 'build_rag_context',
        lambda username, message: ('[1] notes.txt: context', [{'id': 1, 'source': 'notes.txt', 'snippet': 'context', 'score': 1.0}]),
    )

    response = signed_in_client(db).post('/api/chat', json={'message': 'and now?'})

    assert response.status_code == 200
    prompt = sent['prompt']
    assert 'User: What is a closure?' in prompt
    assert 'Assistant: A closure captures its scope.' in prompt
    assert 'Local Context:\n[1] notes.txt: context' in prompt
    assert prompt.rstrip().endswith('Assistant:')


def test_stream_endpoint_sends_prior_turns(monkeypatch, db):
    sent = {}
    stub_model(monkeypatch, sent)
    monkeypatch.setattr(court, 'build_rag_context', lambda username, message: ('', []))

    response = signed_in_client(db).post('/api/chat_stream', json={'message': 'and now?'})
    body = response.get_data(as_text=True)

    assert 'User: What is a closure?' in sent['prompt']
    assert 'Assistant: A closure captures its scope.' in sent['prompt']
    assert '"done"' in body
