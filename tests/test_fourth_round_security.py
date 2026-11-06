import random
import pytest
from diagnostic_browser.policy import Scope
from diagnostic_browser.request_ledger import RequestLedger

@pytest.mark.parametrize('path', [
    '/%6cogin', '/%256cogin', '/%25256cogin', '/%2flogin',
    '/api/%2e%2e/login', '/api/../login', '/%73so', '/%6fauth',
    '/%5clogin', '/%00login', '/%252525256cogin',
])
def test_encoded_auth_paths_fail_closed(path):
    assert not Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')).allowed('https://app.example.org' + path)

def test_normal_routes_remain_authorized():
    scope = Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org'))
    for route in ('/api/orders', '/socket.io/', '/cpdom/events', '/static/app.js'):
        assert scope.allowed('https://app.example.org' + route)

def test_malformed_request_does_not_erase_active_request():
    ledger = RequestLedger(Scope(test_local=True))
    _, hop = ledger.begin({'requestId':'id','request':{'url':'http://127.0.0.1/api/a','method':'GET'}})
    assert hop and ledger.get('id') == hop
    for malformed in (None, [], 3, {'url': []}, {'method': 'GET'}, {'url':'http://127.0.0.1/api/b', 'method': []}):
        old, rejected = ledger.begin({'requestId':'id','request':malformed})
        assert old is None and (rejected is None or not rejected.authorized)
        assert ledger.get('id') == hop

@pytest.mark.parametrize('capacity', [True, False, 0, -1, '5', 2.5, None, [], {}])
def test_invalid_ledger_capacity(capacity):
    with pytest.raises(ValueError):
        RequestLedger(Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')), capacity)

def test_randomized_encoded_auth_and_state_preservation():
    rng = random.Random(8675309)
    ledger = RequestLedger(Scope(test_local=True), capacity=16)
    for i in range(3000):
        key = 'key'+str(i%8)
        _, hop = ledger.begin({'requestId':key,'request':{'url':'http://127.0.0.1/api/x','method':'GET'}})
        assert hop is not None
        before = ledger.get(key)
        ledger.begin({'requestId':key,'request':{'url':rng.choice([None, [], {}, 3]), 'method':'GET'}})
        assert ledger.get(key) == before
        assert len(ledger) <= 16
