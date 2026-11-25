"""Tests for choosing which installed Ollama model answers the chat.

The picker reads /api/models, switches with /api/model, and the choice is stored
per account. Only models Ollama reports as installed can be chosen, and chat
requests must actually send the selected name.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as court  # noqa: E402  (path bootstrap must run first)

def test_stream_shows_an_ollama_error_line(db, monkeypatch):
    installed(monkeypatch, 'llama3:latest')

    class ErrorStream:
        def raise_for_status(self):
            pass

        def iter_lines(self, decode_unicode=False):
            return iter(['{"error": "model failed to load"}'])

    monkeypatch.setattr(court.requests, 'post', lambda url, **kwargs: ErrorStream())

    body = signed_in('alice').post('/api/chat_stream', json={'message': 'hi'}).get_data(as_text=True)

    assert '"type": "error"' in body
    assert 'model failed to load' in body

@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(court, 'USER_DB_FILE', str(tmp_path / 'users.db'))
    monkeypatch.setattr(court, 'DATA_FILE', str(tmp_path / 'storage.json'))
    monkeypatch.setattr(court, 'RAG_FILE', str(tmp_path / 'rag_store.json'))
    court._INSTALLED_MODELS.update(available=False, names=(), expires_at=0.0)
    court.init_user_db()
    court.create_user('alice', 'password123', 'Alice')
    court.create_user('bob', 'password123', 'Bob')
    court.clear_all_login_failures()
    return tmp_path


def installed(monkeypatch, *names):
    payload = {'models': [{'name': name, 'size': 1234} for name in names]}
    monkeypatch.setattr(court, 'is_ollama_available', lambda: (True, payload))


def offline(monkeypatch):
    monkeypatch.setattr(court, 'is_ollama_available', lambda: (False, {}))


def signed_in(username):
    client = court.app.test_client()
    with client.session_transaction() as session:
        session['logged_in'] = True
        session['session_version'] = 0
        session['username'] = username
        session['display_name'] = username.title()
        session['current_chat_index'] = 0
    return client


def select(client, name):
    return client.post('/api/model', json={'model': name})


def captured_payloads(monkeypatch, reply='Hello there'):
    sent = []

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {'response': reply}

    def fake_post(url, **kwargs):
        sent.append(kwargs.get('json'))
        return FakeResponse()

    monkeypatch.setattr(court.requests, 'post', fake_post)
    return sent


def test_lists_the_models_installed_on_this_machine(db, monkeypatch):
    installed(monkeypatch, 'qwen2.5:7b', 'llama3:latest')

    data = signed_in('alice').get('/api/models').get_json()

    assert data['success'] is True
    assert data['ollama_available'] is True
    assert [model['name'] for model in data['models']] == ['llama3:latest', 'qwen2.5:7b']
    assert data['selected'] == court.MODEL


def test_reports_an_offline_ollama_without_failing(db, monkeypatch):
    offline(monkeypatch)

    data = signed_in('alice').get('/api/models').get_json()

    assert data['ollama_available'] is False
    assert data['models'] == []
    assert data['selected'] == court.MODEL


def test_selecting_an_installed_model_is_saved_to_the_account(db, monkeypatch):
    installed(monkeypatch, 'llama3:latest', 'qwen2.5:7b')
    client = signed_in('alice')

    response = select(client, 'qwen2.5:7b')

    assert response.status_code == 200
    assert response.get_json()['model'] == 'qwen2.5:7b'
    assert court.get_user_settings('alice')['model'] == 'qwen2.5:7b'
    assert signed_in('alice').get('/api/models').get_json()['selected'] == 'qwen2.5:7b'


def test_the_choice_survives_a_new_sign_in(db, monkeypatch):
    installed(monkeypatch, 'llama3:latest', 'qwen2.5:7b')
    select(signed_in('alice'), 'qwen2.5:7b')

    page = signed_in('alice').get('/chat').get_data(as_text=True)

    assert 'value="qwen2.5:7b"' in page


def test_an_uninstalled_model_cannot_be_selected(db, monkeypatch):
    installed(monkeypatch, 'llama3:latest')

    response = select(signed_in('alice'), 'qwen2.5:7b')

    assert response.status_code == 400
    assert 'not installed' in response.get_json()['error']
    assert court.get_user_settings('alice')['model'] == ''


def test_switching_models_needs_a_running_ollama(db, monkeypatch):
    offline(monkeypatch)

    response = select(signed_in('alice'), 'llama3:latest')

    assert response.status_code == 503
    assert court.get_user_settings('alice')['model'] == ''


@pytest.mark.parametrize(
    'name',
    ['', '   ', 'bad name', '-starts-with-dash', 'a' * 201, 'llama3\nmalicious'],
)
def test_malformed_model_names_are_refused(db, monkeypatch, name):
    installed(monkeypatch, 'llama3:latest')

    assert select(signed_in('alice'), name).status_code == 400
    assert court.get_user_settings('alice')['model'] == ''


def test_the_selected_model_answers_chat_messages(db, monkeypatch):
    installed(monkeypatch, 'llama3:latest', 'qwen2.5:7b')
    client = signed_in('alice')
    select(client, 'qwen2.5:7b')
    sent = captured_payloads(monkeypatch)

    response = client.post('/api/chat', json={'message': 'hi'})

    assert response.status_code == 200
    assert sent[0]['model'] == 'qwen2.5:7b'


def test_without_a_choice_chat_uses_the_install_default(db, monkeypatch):
    installed(monkeypatch, 'llama3:latest')
    sent = captured_payloads(monkeypatch)

    signed_in('alice').post('/api/chat', json={'message': 'hi'})

    assert sent[0]['model'] == court.MODEL


def test_another_account_keeps_the_default_model(db, monkeypatch):
    installed(monkeypatch, 'llama3:latest', 'qwen2.5:7b')
    select(signed_in('alice'), 'qwen2.5:7b')

    assert court.get_user_settings('bob')['model'] == ''
    assert signed_in('bob').get('/api/models').get_json()['selected'] == court.MODEL


def test_health_reports_the_chosen_model(db, monkeypatch):
    installed(monkeypatch, 'llama3:latest', 'qwen2.5:7b')
    client = signed_in('alice')
    select(client, 'qwen2.5:7b')

    data = client.get('/api/health').get_json()

    assert data['model'] == 'qwen2.5:7b'
    assert data['model_installed'] is True


@pytest.mark.parametrize(
    'method,path',
    [('get', '/api/models'), ('post', '/api/model')],
)
def test_model_endpoints_require_sign_in(db, method, path):
    response = getattr(court.app.test_client(), method)(
        path, json={'model': 'llama3:latest'},
    )

    assert response.status_code == 401


def test_a_latest_tag_matches_the_bare_name(db, monkeypatch):
    installed(monkeypatch, 'court-refusal-v1:latest')
    monkeypatch.setattr(court, 'MODEL', 'court-refusal-v1')

    client = signed_in('alice')
    models = client.get('/api/models').get_json()
    health = client.get('/api/health').get_json()

    assert models['selected'] == 'court-refusal-v1:latest'
    assert health['model'] == 'court-refusal-v1:latest'
    assert health['model_installed'] is True


def test_chat_uses_the_installed_tag_for_a_bare_default(db, monkeypatch):
    installed(monkeypatch, 'court-refusal-v1:latest')
    monkeypatch.setattr(court, 'MODEL', 'court-refusal-v1')
    sent = captured_payloads(monkeypatch)

    signed_in('alice').post('/api/chat', json={'message': 'hi'})

    assert sent[0]['model'] == 'court-refusal-v1:latest'


def test_selecting_the_bare_name_stores_the_installed_tag(db, monkeypatch):
    installed(monkeypatch, 'court-refusal-v1:latest')

    response = select(signed_in('alice'), 'court-refusal-v1')

    assert response.status_code == 200
    assert response.get_json()['model'] == 'court-refusal-v1:latest'
    assert court.get_user_settings('alice')['model'] == 'court-refusal-v1:latest'


def test_a_missing_model_error_says_how_to_fix_it(db, monkeypatch):
    installed(monkeypatch, 'llama3:latest')

    class MissingModelResponse:
        status_code = 404

        def raise_for_status(self):
            raise court.requests.exceptions.HTTPError(
                '404 Client Error', response=self,
            )

        def json(self):
            return {'error': f"model '{court.MODEL}' not found"}

    monkeypatch.setattr(
        court.requests, 'post', lambda url, **kwargs: MissingModelResponse(),
    )

    data = signed_in('alice').post('/api/chat', json={'message': 'hi'}).get_json()

    assert 'cannot use the model' in data['response']
    assert 'not found' in data['response']
    assert f'"{court.MODEL}"' in data['response']
    assert 'Installed: llama3:latest.' in data['response']


def missing_model_error(detail="model 'nope' not found"):
    class MissingModelResponse:
        status_code = 404

        def json(self):
            return {'error': detail}

    return court.requests.exceptions.HTTPError('404 Client Error', response=MissingModelResponse())


def test_the_error_shows_the_name_tried_next_to_the_installed_ones():
    message = court.ollama_error_message(
        missing_model_error(),
        'court-refusal-v1',
        ['court-refusal-v1:latest', 'llama3:latest'],
    )

    assert message.startswith('Error: Ollama cannot use the model "court-refusal-v1"')
    assert 'Installed: court-refusal-v1:latest, llama3:latest.' in message
    assert len(message) < 220


def test_a_long_installed_list_is_capped_for_the_bubble():
    names = [f'model-{index}:latest' for index in range(court.MAX_REPORTED_MODELS + 3)]

    message = court.ollama_error_message(missing_model_error(), 'nope', names)

    assert 'model-0:latest' in message
    assert 'and 3 more' in message
    assert names[-1] not in message


def test_the_error_says_when_ollama_reports_nothing_installed():
    message = court.ollama_error_message(missing_model_error(), 'nope', [])

    assert 'Installed: none reported.' in message


def test_health_reuses_one_lookup_and_the_picker_forces_a_fresh_one(db, monkeypatch):
    calls = []
    monkeypatch.setattr(
        court, 'is_ollama_available',
        lambda: (calls.append(1), (True, {'models': [{'name': court.MODEL}]}))[1],
    )

    client = signed_in('alice')
    client.get('/api/health')
    health = client.get('/api/health').get_json()
    assert len(calls) == 1
    assert health['model'] == court.MODEL
    assert health['model_installed'] is True

    client.get('/api/models')
    assert len(calls) == 2


def test_an_offline_ollama_is_probed_once_per_window(db, monkeypatch):
    calls = []
    monkeypatch.setattr(
        court, 'is_ollama_available', lambda: (calls.append(1), (False, {}))[1],
    )

    client = signed_in('alice')
    first = client.get('/api/health').get_json()
    second = client.get('/api/health').get_json()

    assert len(calls) == 1
    assert first['ollama_available'] is False
    assert second['ollama_available'] is False
    assert second['model_installed'] is False


def test_chat_still_sends_the_stored_model_when_ollama_is_offline(db, monkeypatch):
    offline(monkeypatch)
    sent = captured_payloads(monkeypatch)

    signed_in('alice').post('/api/chat', json={'message': 'hi'})

    assert sent[0]['model'] == court.MODEL


def test_payload_uses_the_given_model_and_falls_back_otherwise(db):
    settings = dict(court.DEFAULT_GENERATION_SETTINGS)
    assert court.build_ollama_payload('prompt', settings, True)['think'] is False
    assert court.build_ollama_payload('prompt', dict(settings, thinking=True), True)['think'] is True
    assert court.build_ollama_payload('prompt', settings, False)['model'] == court.MODEL
    assert court.build_ollama_payload(
        'prompt', settings, False, 'qwen2.5:7b',
    )['model'] == 'qwen2.5:7b'
