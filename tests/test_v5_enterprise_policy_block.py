"""Policy diagnostics prove policy is respected, not evaded."""
import json
from types import SimpleNamespace
import pytest
from diagnostic_browser.environment_policy import (
    inspect_policy_files, classify_navigation_exception
)
from diagnostic_browser.policy import network_code, normalize, Scope
from diagnostic_browser.capture import BrowserFlight


def test_wildcard_block_detected_without_outputting_policy_url_patterns(tmp_path):
    f=tmp_path/'managed.json'
    f.write_text(json.dumps({'URLBlocklist':['*'], 'HomePageLocation':'https://confidential.example/path'}))
    result=inspect_policy_files([f])
    assert result['interpretation']=='WILDCARD_BLOCK_CONFIGURED'
    assert result['actual_navigation_verified'] is False
    assert 'confidential' not in str(result)
    assert result['administrator_override_attempted'] is False


def test_allowlist_only_means_possible_exception_not_proof(tmp_path):
    f=tmp_path/'managed.json'
    f.write_text(json.dumps({'URLBlocklist':['*'], 'URLAllowlist':['https://secret.example']}))
    result=inspect_policy_files([f])
    assert result['interpretation']=='WILDCARD_BLOCK_WITH_POSSIBLE_EXCEPTIONS'
    assert result['actual_navigation_verified'] is False
    assert 'secret.example' not in str(result)


def test_non_json_and_invalid_policy_ignored(tmp_path):
    good=tmp_path/'good.json'; good.write_text('{}')
    bad=tmp_path/'bad.json'; bad.write_text('NOT VALID JSON')
    result=inspect_policy_files([good,bad,tmp_path/'absent.json'])
    assert result['examined_files']==1
    assert result['unreadable_files']==1


@pytest.mark.parametrize(('error','code'), [
    ('Page.goto: net::ERR_BLOCKED_BY_ADMINISTRATOR at https://sensitive.example/patient/123','BROWSER_POLICY_BLOCKED'),
    ('net::ERR_BLOCKED_BY_CLIENT at https://secret.example','BROWSER_REQUEST_BLOCKED'),
    ('net::ERR_CERT_AUTHORITY_INVALID at https://secret.example','NAVIGATION_FAILED'),
])
def test_classifies_without_retaining_raw_exception(error,code):
    assert classify_navigation_exception(Exception(error)) == code
    assert network_code(error) in {'ERR_BLOCKED_BY_ADMINISTRATOR','ERR_BLOCKED_BY_CLIENT','ERR_CERT_AUTHORITY_INVALID'}
    event=normalize('health','error',{'target':'browser','code':code})
    assert 'sensitive.example' not in str(event)


@pytest.mark.asyncio
async def test_browser_reports_policy_block_and_does_not_falsely_claim_navigation(monkeypatch,tmp_path):
    flight=BrowserFlight(SimpleNamespace(accept=lambda *args: None),tmp_path,None,headless=True)
    class FakePage:
        url='about:blank'
        async def goto(self, url, **kwargs):
            raise RuntimeError('net::ERR_BLOCKED_BY_ADMINISTRATOR https://private.test/token=secret')
    class Context:
        pages=[FakePage()]
        def on(self, name, fn):pass
    class BrowserController:
        async def launch_persistent_context(self,**kwargs):return Context()
    class PW:
        chromium=BrowserController()
    class Manager:
        async def start(self):return PW()
    from diagnostic_browser import capture
    monkeypatch.setattr(capture,'async_playwright',lambda:Manager())
    async def fake_attach(page):
        flight.pages[page]=SimpleNamespace(ready=True,closed=False)
    monkeypatch.setattr(flight,'attach',fake_attach)
    events=[]
    flight.recorder=SimpleNamespace(accept=lambda *x:events.append(x))
    page=await flight.start('https://example.org')
    assert page.url=='about:blank'
    assert flight.status=='DEGRADED'
    assert flight.navigation_blocked_by_policy is True
    assert events==[('health','error',{'target':'browser','code':'BROWSER_POLICY_BLOCKED'})]
    flight._repair_task.cancel()
    try:await flight._repair_task
    except __import__('asyncio').CancelledError:pass


@pytest.mark.asyncio
async def test_policy_blocked_network_request_separated_from_vendor_failure(tmp_path):
    from diagnostic_browser.capture import PageCapture
    from diagnostic_browser.recorder import Recorder
    from diagnostic_browser.store import EvidenceStore
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    recorder=Recorder(store, auto_incident=False)
    cap=PageCapture(None,None,recorder,Scope(test_local=True))
    await recorder.start()
    try:
        cap.on_request({'requestId':'req1','request':{'url':'http://127.0.0.1/api/test?password=NEVERSEEN','method':'GET'}})
        cap.on_failed({'requestId':'req1','errorText':'net::ERR_BLOCKED_BY_ADMINISTRATOR https://private.example/PHI'})
        await recorder.flush()
        records=store.events()
        assert [r['kind'] for r in records] == ['health','network_failure']
        assert records[0]['fields']['code']=='BROWSER_POLICY_BLOCKED'
        assert records[1]['fields']['error_code']=='ERR_BLOCKED_BY_ADMINISTRATOR'
        assert 'NEVERSEEN' not in str(records) and 'private.example' not in str(records)
    finally:
        await recorder.stop()
        store.close()
