"""Deterministic adversarial type fuzz and request lifecycle stress regression."""
import random
import pytest
from diagnostic_browser.policy import normalize, UnsafeEvent, Scope, network_code
from diagnostic_browser.request_ledger import RequestLedger

BAD = [None, False, True, 3.14, 4, [], {}, ['GET'], {'x': 2}, ('GET',), b'GET', set(), object()]

@pytest.mark.parametrize('field', ['resource','socket_state','target','reason','coverage','cache','service_worker','protocol','method','route','error_class','error_code','code','detail_code'])
@pytest.mark.parametrize('bad', BAD)
def test_fuzz_unhashable_enumerations_are_rejected(field,bad):
    with pytest.raises(UnsafeEvent):
        normalize('health','info',{field:bad})

@pytest.mark.parametrize('bad', BAD)
def test_fuzz_untrusted_event_metadata_types(bad):
    with pytest.raises(UnsafeEvent): normalize(bad,'info',{})
    with pytest.raises(UnsafeEvent): normalize('health',bad,{})

@pytest.mark.parametrize('bad', BAD)
def test_fuzz_bad_field_keys(bad):
    if isinstance(bad, (list,dict,set)):
        # unhashable objects cannot be dictionary keys: test the outer container instead
        if not isinstance(bad, dict):
            with pytest.raises(UnsafeEvent): normalize('health','info',bad)
    elif bad not in (None,):
        with pytest.raises(UnsafeEvent): normalize('health','info',{bad:1})

@pytest.mark.parametrize('bad', BAD)
def test_fuzz_request_ledger_malformed_event(bad):
    ledger=RequestLedger(Scope(test_local=True),capacity=3)
    assert ledger.begin(bad)==(None,None)
    assert len(ledger)==0

def test_fuzz_request_ledger_bounded_stress_and_redirects():
    rng=random.Random(20261106)
    ledger=RequestLedger(Scope(test_local=True),capacity=17)
    for n in range(5000):
        event={'requestId':str(rng.randint(0,60)), 'request':{'url':rng.choice(['https://login.okta.com/a','https://a.example.org/api/x?secret=y','http://127.0.0.1:9000/x','file:///etc/passwd']), 'method':rng.choice(['GET','POST','bad'])}}
        if rng.random()<.3:event['redirectResponse']={}
        old,new=ledger.begin(event)
        assert new is not None
        assert len(ledger)<=17
        assert len(new.reference)==32 and len(new.chain)==32
        if rng.random()<.4:ledger.finish(event['requestId'])
    assert ledger.evictions>0

def test_fuzz_network_code_does_not_retain_secret():
    sample_value='VERY_PRIVATE_PATIENT_INFORMATION'
    for size in (0, 1, 512, 8192):
        assert network_code(sample_value*size) == 'ERR_OTHER'


@pytest.mark.parametrize('bad', BAD)
def test_fuzz_request_nested_malformed_values(bad):
    ledger=RequestLedger(Scope(test_local=True),capacity=2)
    old,new=ledger.begin({'requestId':'r','request':{'url':bad,'method':bad}})
    assert old is None
    assert new is not None and not new.authorized
    assert len(ledger)==1

@pytest.mark.parametrize('bad', BAD)
def test_fuzz_invalid_network_error_type(bad):
    assert network_code(bad)=='ERR_OTHER'

def test_fuzz_invalid_coverage_and_numeric_values():
    for value in [float('nan'),float('inf'),-1,10000001,True,[],{},'100']:
        for key in ('count','line','column','sequence'):
            with pytest.raises(UnsafeEvent): normalize('health','info',{key:value})

def test_fuzz_cross_domain_redirect_never_authorizes_excluded_hop():
    ledger=RequestLedger(Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')),capacity=2)
    _,first=ledger.begin({'requestId':'r','request':{'url':'https://a.example.org/api/x','method':'GET'}})
    old,second=ledger.begin({'requestId':'r','redirectResponse':{'status':302},'request':{'url':'https://login.okta.com/signin','method':'GET'}})
    assert first.authorized and old==first
    assert not second.authorized
    assert second.chain==first.chain and second.reference!=first.reference
