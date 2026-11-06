import pytest
from diagnostic_browser.analysis import compare,count_signatures,fingerprint
from diagnostic_browser.store import EvidenceStore

def test_fingerprint_stable_and_comparison():
    event=dict(kind='http_error',severity='error',fields=dict(status=500,route='api',method='GET'))
    assert fingerprint(event)==fingerprint(dict(event,extra='ignored'))
    result=compare({'a':3,'b':2},{'a':1,'c':5})
    assert {x['fingerprint']:x['classification'] for x in result}=={'a':'PERSISTENT','b':'NOT_OBSERVED','c':'NEW'}

def test_baseline_known_issue_registry(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    try:
        store.add('js_exception','error',{'error_class':'TypeError','line':22})
        b=store.save_baseline()
        assert b['signature_count']==1
        store.add('http_error','error',{'status':500,'route':'api','method':'GET'})
        rows=store.compare_baseline()['differences']
        assert {x['classification'] for x in rows}=={'NEW','NOT_OBSERVED'}
        # A fresh recurrence after the baseline is persistent; old baseline data
        # must not be counted a second time as though it were a new observation.
        store.add('js_exception','error',{'error_class':'TypeError','line':22})
        rows=store.compare_baseline()['differences']
        assert {x['classification'] for x in rows}=={'NEW','PERSISTENT'}
        f=rows[0]['fingerprint']
        store.upsert_issue(f,'TS-12345','OPEN')
        assert store.known_issues()[0]['ticket']=='TS-12345'
        with pytest.raises(ValueError):store.upsert_issue(f,'patient:Mary','OPEN')
    finally:store.close()
