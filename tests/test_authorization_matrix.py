"""Two-account authorization matrix for the chat and RAG APIs.

Every route scopes its data by the account in the signed session, so the
attacker's index is resolved against *their* chat list and *their* RAG store.
These tests pin that down route by route: Bob, signed in, guesses the indices
and document IDs that belong to Alice and must get a 404/400 with Alice's data
untouched, and the read/export paths must never contain a byte of it.

The fixture gives Alice three chats and Bob one, so indices 1 and 2 are valid
for Alice and out of range for Bob: exactly the "guess the victim's index" case.
"""

import sys
from io import BytesIO
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as court  # noqa: E402  (path bootstrap must run first)

ALICE_MARK = 'alice-secret-marker'
BOB_MARK = 'bob-secret-marker'
ALICE_DOC_ID = 'alice-doc-1234'
ALICE_DOC_NAME = 'alice-private.txt'
BOB_DOC_ID = 'bob-doc-5678'
BOB_DOC_NAME = 'bob-notes.txt'


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail loudly instead of reaching Ollama; individual tests opt back in."""

    def explode(*args, **kwargs):
        raise AssertionError('this test tried to make a network request')

    monkeypatch.setattr(court.requests, 'post', explode)


@pytest.fixture
def accounts(tmp_path, monkeypatch):
    monkeypatch.setattr(court, 'USER_DB_FILE', str(tmp_path / 'users.db'))
    monkeypatch.setattr(court, 'DATA_FILE', str(tmp_path / 'storage.json'))
    monkeypatch.setattr(court, 'RAG_FILE', str(tmp_path / 'rag_store.json'))
    court.init_user_db()
    court.create_user('alice', 'password123', 'Alice')
    court.create_user('bob', 'password123', 'Bob')

    court.save_chats('alice', [
        {
            'title': f'alice-chat-{index}',
            'messages': [{
                'type': 'ai',
                'message': f'<p>{ALICE_MARK}-{index}</p>',
                'sources': [],
            }],
            'tags': [f'alice-tag-{index}'],
        }
        for index in range(3)
    ])
    court.save_chats('bob', [{
        'title': 'bob-chat',
        'messages': [{'type': 'ai', 'message': f'<p>{BOB_MARK}</p>', 'sources': []}],
        'tags': ['bob-tag'],
    }])

    court.save_user_rag('alice', {
        'enabled': True,
        'documents': [{
            'id': ALICE_DOC_ID,
            'name': ALICE_DOC_NAME,
            'uploaded_at': '2026-01-01T00:00:00',
            'chunks': [{'text': f'{ALICE_MARK} document body', 'embedding': None}],
        }],
    })
    court.save_user_rag('bob', {
        'enabled': True,
        'documents': [{
            'id': BOB_DOC_ID,
            'name': BOB_DOC_NAME,
            'uploaded_at': '2026-01-01T00:00:00',
            'chunks': [{'text': f'{BOB_MARK} document body', 'embedding': None}],
        }],
    })
    return tmp_path


def client_for(username, current_chat_index=0):
    client = court.app.test_client()
    with client.session_transaction() as session:
        session['logged_in'] = True
        session['session_version'] = 0
        session['username'] = username
        session['current_chat_index'] = current_chat_index
    return client


def alice_state():
    return {
        'chats': court.load_chats('alice'),
        'rag': court.get_user_rag('alice'),
        'settings': court.get_user_settings('alice'),
    }


def assert_no_alice_data(text):
    for needle in (ALICE_MARK, ALICE_DOC_ID, ALICE_DOC_NAME, 'alice-chat-'):
        assert needle not in text, f'{needle!r} leaked to another account'


class FakeOllamaResponse:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        return None

    def json(self):
        return {'response': self.text}

    def iter_lines(self, decode_unicode=False):
        yield '{"response": "%s"}' % self.text


def fake_ollama(calls, text):
    def post(url, json=None, timeout=None, stream=False, **kwargs):
        calls.append({'url': url, 'payload': json})
        return FakeOllamaResponse(text)

    return post


def generation_prompt(calls):
    """The prompt sent to the chat model, skipping embedding requests."""
    generation = [call for call in calls if 'options' in call['payload']]
    assert generation, 'no generation request was made'
    return generation[0]['payload']['prompt']


GUESSED_INDEX_ROUTES = [
    ('load', 'post', '/api/load_chat/{index}', None),
    ('rename', 'post', '/api/rename_chat/{index}', {'title': 'stolen'}),
    ('delete', 'post', '/api/delete_chat/{index}', None),
    ('add-tag', 'post', '/api/add_tag/{index}', {'tag': 'stolen'}),
    ('remove-tag', 'post', '/api/remove_tag/{index}', {'tag': 'alice-tag-1'}),
    ('summarize', 'post', '/api/summarize_chat/{index}', None),
]


@pytest.mark.parametrize('index', [1, 2])
@pytest.mark.parametrize(
    'route,method,template,payload',
    GUESSED_INDEX_ROUTES,
    ids=[route for route, *_ in GUESSED_INDEX_ROUTES],
)
def test_guessed_chat_index_reaches_nothing_of_the_other_account(
    accounts, route, method, template, payload, index,
):
    before = alice_state()
    client = client_for('bob')

    response = getattr(client, method)(template.format(index=index), json=payload)

    assert response.status_code == 400
    assert response.get_json()['error'] == 'Invalid chat index'
    assert_no_alice_data(response.get_data(as_text=True))
    assert alice_state() == before


@pytest.mark.parametrize(
    'route,method,template,payload',
    GUESSED_INDEX_ROUTES,
    ids=[route for route, *_ in GUESSED_INDEX_ROUTES],
)
def test_shared_index_modifies_only_the_callers_own_chat(
    accounts, route, method, template, payload,
):
    # Index 0 exists for both accounts. Whatever the route does must land on
    # Bob's chat and leave Alice's identically positioned chat alone.
    alice_before = alice_state()
    client = client_for('bob')

    response = getattr(client, method)(template.format(index=0), json=payload)

    assert response.status_code in (200, 400)
    assert_no_alice_data(response.get_data(as_text=True))
    assert alice_state() == alice_before


def test_rename_at_a_shared_index_renames_the_callers_chat_only(accounts):
    client = client_for('bob')

    response = client.post('/api/rename_chat/0', json={'title': 'renamed by bob'})

    assert response.status_code == 200
    assert court.load_chats('bob')[0]['title'] == 'renamed by bob'
    assert court.load_chats('alice')[0]['title'] == 'alice-chat-0'


def test_delete_at_a_shared_index_deletes_the_callers_chat_only(accounts):
    client = client_for('bob')

    response = client.post('/api/delete_chat/0')

    assert response.status_code == 200
    assert court.load_chats('bob') == []
    assert len(court.load_chats('alice')) == 3


def test_chat_list_and_export_contain_only_the_callers_chats(accounts):
    client = client_for('bob')

    listing = client.get('/api/chats').get_json()
    export = client.get('/api/chats?full=1')

    assert [chat['title'] for chat in listing['chats']] == ['bob-chat']
    assert export.status_code == 200
    body = export.get_data(as_text=True)
    assert BOB_MARK in body
    assert_no_alice_data(body)


def test_chat_page_renders_only_the_callers_chat(accounts):
    body = client_for('bob').get('/chat').get_data(as_text=True)

    assert BOB_MARK in body
    assert_no_alice_data(body)


def test_search_never_returns_the_other_accounts_messages(accounts):
    client = client_for('bob')

    shared_term = client.post('/api/search_messages', json={'query': 'secret-marker'}).get_json()
    alice_term = client.post('/api/search_messages', json={'query': ALICE_MARK}).get_json()

    assert shared_term['results']
    assert all(BOB_MARK in result['message'] for result in shared_term['results'])
    assert alice_term['results'] == []


def test_chat_generation_uses_only_the_callers_history(accounts, monkeypatch):
    calls = []
    monkeypatch.setattr(court.requests, 'post', fake_ollama(calls, 'bob reply'))
    client = client_for('bob', current_chat_index=0)

    response = client.post('/api/chat', json={'message': 'hello there'})

    assert response.status_code == 200
    assert_no_alice_data(response.get_data(as_text=True))
    prompt = generation_prompt(calls)
    assert BOB_MARK in prompt
    assert ALICE_MARK not in prompt


def test_stream_with_a_guessed_index_creates_a_chat_for_the_caller(accounts, monkeypatch):
    calls = []
    monkeypatch.setattr(court.requests, 'post', fake_ollama(calls, 'bob streamed'))
    before = alice_state()
    # Index 1 is Alice's second chat and out of range for Bob.
    client = client_for('bob', current_chat_index=1)

    response = client.post('/api/chat_stream', json={'message': 'hello there'})
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'bob streamed' in body
    assert_no_alice_data(body)
    assert ALICE_MARK not in generation_prompt(calls)
    assert len(court.load_chats('bob')) == 2
    assert alice_state() == before


def test_summary_is_built_from_the_callers_chat_only(accounts, monkeypatch):
    calls = []
    monkeypatch.setattr(court.requests, 'post', fake_ollama(calls, 'a short summary'))
    client = client_for('bob')

    response = client.post('/api/summarize_chat/0')

    assert response.status_code == 200
    prompt = generation_prompt(calls)
    assert BOB_MARK in prompt
    assert ALICE_MARK not in prompt


def test_import_writes_only_the_callers_store(accounts):
    before = alice_state()
    client = client_for('bob')

    response = client.post('/api/import_chats', json={'imported_chats': {
        'chats': [{
            'title': 'imported by bob',
            'messages': [{'type': 'ai', 'message': 'imported body', 'sources': []}],
            'tags': [],
        }],
        'system_prompt': 'imported prompt',
    }})

    assert response.status_code == 200
    assert alice_state() == before
    assert [chat['title'] for chat in court.load_chats('bob')] == ['imported by bob']


def test_new_chat_is_created_for_the_caller_only(accounts):
    before = alice_state()

    response = client_for('bob').post('/api/new_chat')

    assert response.status_code == 200
    assert len(court.load_chats('bob')) == 2
    assert alice_state() == before


@pytest.mark.parametrize('path', ['/api/rag/status', '/api/rag/documents'])
def test_rag_reads_list_only_the_callers_documents(accounts, path):
    response = client_for('bob').get(path)

    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert BOB_DOC_ID in body
    assert BOB_DOC_NAME in body
    assert_no_alice_data(body)


def test_rag_rename_of_the_other_accounts_document_is_not_found(accounts):
    before = alice_state()

    response = client_for('bob').post(
        f'/api/rag/rename/{ALICE_DOC_ID}', json={'name': 'stolen.txt'},
    )

    assert response.status_code == 404
    assert court.get_user_rag('alice')['documents'][0]['name'] == ALICE_DOC_NAME
    assert alice_state() == before


def test_rag_delete_of_the_other_accounts_document_is_not_found(accounts):
    before = alice_state()

    response = client_for('bob').post(f'/api/rag/delete/{ALICE_DOC_ID}')

    assert response.status_code == 404
    assert [doc['id'] for doc in court.get_user_rag('alice')['documents']] == [ALICE_DOC_ID]
    assert alice_state() == before


def test_rag_rename_and_delete_still_work_on_the_callers_own_document(accounts):
    client = client_for('bob')

    renamed = client.post(f'/api/rag/rename/{BOB_DOC_ID}', json={'name': 'renamed.txt'})

    assert renamed.status_code == 200
    assert [doc['name'] for doc in court.get_user_rag('bob')['documents']] == ['renamed.txt']

    deleted = client.post(f'/api/rag/delete/{BOB_DOC_ID}')

    assert deleted.status_code == 200
    assert court.get_user_rag('bob')['documents'] == []
    assert [doc['id'] for doc in court.get_user_rag('alice')['documents']] == [ALICE_DOC_ID]


def test_rag_upload_lands_in_the_callers_store_only(accounts, monkeypatch):
    monkeypatch.setattr(court, 'get_embedding', lambda text: None)
    before = alice_state()

    response = client_for('bob').post(
        '/api/rag/upload',
        data={'file': (BytesIO(b'bob upload body'), 'bob-upload.txt')},
        content_type='multipart/form-data',
    )

    assert response.status_code == 200
    assert alice_state() == before
    assert 'bob-upload.txt' in [doc['name'] for doc in court.get_user_rag('bob')['documents']]


def test_rag_toggle_does_not_touch_the_other_account(accounts):
    before = alice_state()

    response = client_for('bob').post('/api/rag/toggle', json={'enabled': False})

    assert response.status_code == 200
    assert court.get_user_rag('bob')['enabled'] is False
    assert alice_state() == before


def test_rag_clear_empties_only_the_callers_documents(accounts):
    response = client_for('bob').post('/api/rag/clear')

    assert response.status_code == 200
    assert court.get_user_rag('bob')['documents'] == []
    assert [doc['id'] for doc in court.get_user_rag('alice')['documents']] == [ALICE_DOC_ID]


def test_privacy_wipe_deletes_only_the_callers_data(accounts):
    before = alice_state()

    response = client_for('bob').post('/api/privacy/wipe')

    assert response.status_code == 200
    assert court.load_chats('bob') == []
    assert court.get_user_rag('bob')['documents'] == []
    assert alice_state() == before


UNAUTHENTICATED_ROUTES = [
    ('GET', '/api/chats'),
    ('POST', '/api/new_chat'),
    ('POST', '/api/load_chat/0'),
    ('POST', '/api/rename_chat/0'),
    ('POST', '/api/delete_chat/0'),
    ('POST', '/api/add_tag/0'),
    ('POST', '/api/remove_tag/0'),
    ('POST', '/api/summarize_chat/0'),
    ('POST', '/api/search_messages'),
    ('POST', '/api/import_chats'),
    ('POST', '/api/chat'),
    ('POST', '/api/chat_stream'),
    ('POST', '/api/privacy/wipe'),
    ('GET', '/api/rag/status'),
    ('GET', '/api/rag/documents'),
    ('POST', '/api/rag/toggle'),
    ('POST', '/api/rag/clear'),
    ('POST', '/api/rag/upload'),
    ('POST', '/api/rag/rename/x'),
    ('POST', '/api/rag/delete/x'),
]


@pytest.mark.parametrize('method,path', UNAUTHENTICATED_ROUTES)
def test_chat_and_rag_routes_require_a_signed_in_session(accounts, method, path):
    client = court.app.test_client()

    response = client.open(path, method=method, json={} if method == 'POST' else None)

    assert response.status_code == 401
    assert alice_state()['chats'][0]['title'] == 'alice-chat-0'
