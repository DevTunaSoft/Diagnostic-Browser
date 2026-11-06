"""Nested CDP target wire-format and privacy fault tests (synthetic only)."""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from diagnostic_browser.capture import PageCapture
from diagnostic_browser.policy import Scope


@pytest.mark.asyncio
async def test_nested_worker_events_are_scoped_sanitized_and_not_paused():
    seen=[]
    store=SimpleNamespace(set_coverage=Mock())
    rec=SimpleNamespace(store=store,stats={},accept=lambda kind,level,fields:seen.append((kind,level,fields)))
    page=SimpleNamespace(url='https://dispatch.example.org/dispatch')
    capture=PageCapture(None,page,rec,Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')))
    class FakeSession:
        def __init__(self):self.sent=[]
        async def send(self,method,params):self.sent.append((method,params));return {}
    fake=FakeSession();capture.session=fake
    capture.on_nested_attach({'sessionId':'sid-a','targetInfo':{
        'url':'https://dispatch.example.org/a.js','type':'worker'}})
    await asyncio.sleep(.1)
    assert ('Runtime.enable',{}) in [(json.loads(p['message'])['method'],json.loads(p['message'])['params'])
                                     for m,p in fake.sent if m=='Target.sendMessageToTarget']
    assert all('waitForDebuggerOnStart' not in p or p['waitForDebuggerOnStart'] is False
               for m,p in fake.sent)
    capture.on_nested_message({'sessionId':'sid-a','message':json.dumps({
        'method':'Runtime.executionContextCreated',
        'params':{'context':{'id':123,'origin':'https://dispatch.example.org'}}})})
    canary='SECRET_PASSWORD_SEED_491'
    capture.on_nested_message({'sessionId':'sid-a','message':json.dumps({
        'method':'Runtime.exceptionThrown','params':{'exceptionDetails':{
            'executionContextId':123, 'text':canary,'url':'https://dispatch.example.org/a.js',
            'exception':{'className':'TypeError','description':canary}}}})})
    assert any(kind=='js_exception' and f['error_class']=='TypeError' for kind,_,f in seen)
    assert canary not in str(seen)
    capture.on_nested_message({'sessionId':'sid-a','message':json.dumps({
        'method':'Runtime.consoleAPICalled','params':{'executionContextId':123,
            'type':'error','args':[{'value':canary}]}})})
    assert canary not in str(seen)
    capture.on_nested_detach({'sessionId':'sid-a'})
    assert 'sid-a' not in capture.nested_targets
    capture.close()


@pytest.mark.asyncio
async def test_nested_targets_exclude_auth_origins_and_oversize_messages():
    seen=[]
    store=SimpleNamespace(set_coverage=Mock())
    rec=SimpleNamespace(store=store,stats={},accept=lambda *x:seen.append(x))
    page=SimpleNamespace(url='https://dispatch.example.org')
    cap=PageCapture(None,page,rec,Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')))
    async def send(*args): return {}
    cap.session=SimpleNamespace(send=send)
    cap.on_nested_attach({'sessionId':'auth-worker','targetInfo':{
        'type':'service_worker','url':'https://company.okta.com/token'}})
    cap.on_nested_message({'sessionId':'auth-worker','message':json.dumps({
        'method':'Runtime.exceptionThrown','params':{'exceptionDetails':{'text':'SECRET'}}})})
    assert not seen
    cap.on_nested_attach({'sessionId':'allowed-worker','targetInfo':{
        'type':'worker','url':'https://dispatch.example.org/js/main.js'}})
    cap.on_nested_message({'sessionId':'allowed-worker','message':'X'*262145})
    assert len(seen)==1 and seen[0][0]=='collection_gap'
    assert 'SECRET' not in str(seen)
    cap.close()
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_recursive_nested_worker_commands_route_through_parent():
    store=SimpleNamespace(set_coverage=Mock())
    rec=SimpleNamespace(store=store,stats={},accept=Mock())
    page=SimpleNamespace(url='https://dispatch.example.org')
    cap=PageCapture(None,page,rec,Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')))
    sent=[]
    class Session:
        async def send(self,method,params):sent.append((method,params))
    cap.session=Session()
    cap.on_nested_attach({'sessionId':'parent','targetInfo':{
        'type':'worker','url':'https://dispatch.example.org/one.js'}})
    cap.on_nested_message({'sessionId':'parent','message':json.dumps({
        'method':'Target.attachedToTarget','params':{'sessionId':'child','targetInfo':{
        'type':'worker','url':'https://dispatch.example.org/two.js'}}})})
    await asyncio.sleep(.2)
    nested_payloads=[json.loads(p['message']) for m,p in sent if m=='Target.sendMessageToTarget']
    assert any(payload.get('method')=='Target.sendMessageToTarget'
               and payload.get('params',{}).get('sessionId')=='child' for payload in nested_payloads)
    cap.close()

@pytest.mark.asyncio
async def test_real_store_nested_coverage_and_export_privacy(tmp_path):
    """Full synthetic nested event -> recorder -> database -> vendor ZIP path."""
    import zipfile
    from diagnostic_browser.recorder import Recorder
    from diagnostic_browser.store import EvidenceStore
    from diagnostic_browser.reports import export_bundle
    store=EvidenceStore(tmp_path,allow_test_plaintext=True)
    recorder=Recorder(store, auto_incident=False)
    await recorder.start()
    page=SimpleNamespace(url='https://dispatch.example.org')
    cap=PageCapture(None,page,recorder,Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')))
    class Session:
        async def send(self,method,params):return {}
    cap.session=Session()
    canary='NEVER_STORE_TOKEN_VALUE_583920'
    try:
        cap.on_nested_attach({'sessionId':'worker-private-session','targetInfo':{
            'type':'service_worker','url':'https://dispatch.example.org/assets/sw.js'}})
        def event(name, params):
            cap.on_nested_message({'sessionId':'worker-private-session','message':
                                   json.dumps({'method':name,'params':params})})
        event('Network.requestWillBeSent',{'requestId':'req-1',
            'request':{'url':'https://dispatch.example.org/api/update?token='+canary,'method':'POST'}})
        event('Network.responseReceived',{'requestId':'req-1','type':'Fetch',
            'response':{'url':'https://dispatch.example.org/api/update?token='+canary,'status':500}})
        event('Network.loadingFinished',{'requestId':'req-1'})
        event('Runtime.executionContextCreated',{'context':{'id':7,'origin':'https://dispatch.example.org'}})
        event('Runtime.exceptionThrown',{'exceptionDetails':{
            'executionContextId':7,'url':'https://dispatch.example.org/js/main.js',
            'text':canary,'exception':{'className':'TypeError','description':canary}}})
        await recorder.flush(strict=True)
        saved=store.events()
        assert {'http_error','js_exception'} <= {e['kind'] for e in saved}
        assert any(e['fields'].get('route')=='api' for e in saved)
        assert any(e['state']=='ACTIVE' for e in store.coverage())
        assert canary not in str(saved)
        result=export_bundle(store,tmp_path/'test-vendor.zip')
        with zipfile.ZipFile(result['path']) as bundle:
            assert bundle.testzip() is None
            for name in bundle.namelist():
                assert canary.encode() not in bundle.read(name), name
    finally:
        cap.close()
        await recorder.stop()
        store.close()

@pytest.mark.asyncio
async def test_many_nested_targets_are_bounded_without_secret_leaks():
    seen=[]
    store=SimpleNamespace(set_coverage=Mock())
    rec=SimpleNamespace(store=store,stats={},accept=lambda *e:seen.append(e))
    page=SimpleNamespace(url='https://dispatch.example.org')
    cap=PageCapture(None,page,rec,Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')))
    async def send(method,params):return {}
    cap.session=SimpleNamespace(send=send)
    for i in range(300):
        cap.on_nested_attach({'sessionId':'nested-'+str(i),'targetInfo':{
            'type':'worker','url':'https://dispatch.example.org/w.js'}})
    await asyncio.sleep(.1)
    assert len(cap.nested_targets)==256
    assert any(e[0]=='collection_gap' and e[2].get('reason')=='queue_full' for e in seen)
    cap.close()
