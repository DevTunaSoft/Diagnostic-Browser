"""Third-round novel size-bound, malformed-state and recovery fuzz checks."""
import random
from diagnostic_browser.policy import Scope, network_code
from diagnostic_browser.request_ledger import RequestLedger


def test_oversized_request_ids_cannot_exhaust_ledger_memory():
    ledger = RequestLedger(Scope(test_local=True), capacity=3)
    for n in range(1, 90):
        old, new = ledger.begin({'requestId': 'a' * (256+n*1000), 'request': {'url': 'http://127.0.0.1/', 'method': 'GET'}})
        assert old is new is None
        assert len(ledger) == 0
    assert ledger.rejected == 89


def test_oversized_url_fails_closed_even_for_allowed_host():
    scope = Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org'))
    assert scope.allowed('https://a.example.org/api/x')
    assert not scope.allowed('https://a.example.org/api/' + 'x'*20000)
    assert scope.category('https://a.example.org/api/' + 'x'*20000) is None


def test_ledger_bounded_randomized_churn_and_reset():
    rng = random.Random(0xFA117)
    ledger = RequestLedger(Scope(test_local=True), capacity=7)
    for i in range(12000):
        key = 'id'+str(rng.randrange(500))
        if rng.randrange(4) == 0:
            ledger.finish(key)
        else:
            ledger.begin({'requestId': key, 'request': {'url': rng.choice(['http://127.0.0.1/api/x', 'https://login.okta.com', 'javascript:alert(1)']), 'method': 'GET'}, 'redirectResponse': {} if rng.randrange(3) == 0 else None})
        assert len(ledger) <= 7
    ledger.reset()
    assert len(ledger) == 0


def test_network_error_large_untrusted_string_is_bounded():
    assert network_code('X'*100000 + ' ERR_CONNECTION_RESET') == 'ERR_OTHER'
    assert network_code('ERR_CONNECTION_RESET ' + 'X'*100000) == 'ERR_CONNECTION_RESET'


def test_ai_backend_malformed_completion_fails_safely(monkeypatch, tmp_path):
    import pytest
    from diagnostic_browser import offline_ai
    fake_model = tmp_path / 'model.gguf'
    fake_model.write_bytes(b'x' * (1024*1024+1))
    monkeypatch.setattr(offline_ai, 'model_path', lambda: fake_model)
    for response in (None, [], {}, {'choices': []}, {'choices': None}, {'choices': [None]}, {'choices': [{'text': 3}]}):
        class FakeModel:
            def __init__(self, **kwargs): pass
            def create_completion(self, **kwargs): return response
        with pytest.raises(RuntimeError, match='invalid local inference response'):
            offline_ai.infer([], model_factory=FakeModel)
