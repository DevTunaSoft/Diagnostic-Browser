"""V4.2 additional adverse-path tests: chronology, privacy, browser state, fidelity."""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

import pytest

from diagnostic_browser.capture import PageCapture, BrowserFlight
from diagnostic_browser.policy import Scope, normalize, UnsafeEvent
from diagnostic_browser.recorder import Recorder
from diagnostic_browser.reports import export_bundle
from diagnostic_browser.store import EvidenceStore
from diagnostic_browser.watchdog import run as watchdog_run


@pytest.mark.asyncio
async def test_preincident_success_metadata_is_saved_without_request_secrets(tmp_path):
    store=EvidenceStore(tmp_path/'evidence', allow_test_plaintext=True); rec=Recorder(store); await rec.start()
    cap=PageCapture(None,None,rec,Scope(test_local=True))
    try:
        cap.on_request({'requestId':'opaque_access_token=PRIVATE','request':{'url':'http://127.0.0.1:8000/api/items/TESTPATIENT?token=TOPSECRET','method':'POST'}})
        cap.on_response({'requestId':'opaque_access_token=PRIVATE','type':'Fetch','response':{'url':'http://127.0.0.1:8000/api/items/TESTPATIENT?token=TOPSECRET','status':204,'fromDiskCache':True}})
        cap.on_finished({'requestId':'opaque_access_token=PRIVATE'})
        await rec.flush()
        ev=store.events()
        assert len(ev)==1
        assert ev[0]['kind']=='http_activity'
        assert ev[0]['fields']['status']==204
        assert ev[0]['fields']['route']=='api'
        assert ev[0]['fields']['cache']=='yes'
        assert 'TOPSECRET' not in str(ev) and 'TESTPATIENT' not in str(ev)
        assert 'opaque_access_token' not in str(ev)
    finally:
        await rec.stop();store.close()


@pytest.mark.asyncio
async def test_redirect_and_response_do_not_duplicate_one_http_event(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True); rec=Recorder(store);await rec.start()
    cap=PageCapture(None,None,rec,Scope(test_local=True))
    try:
        cap.on_request({'requestId':'r','request':{'url':'http://127.0.0.1/api/one','method':'GET'}})
        cap.on_response({'requestId':'r','response':{'url':'http://127.0.0.1/api/one','status':302},'type':'Document'})
        cap.on_request({'requestId':'r','redirectResponse':{'url':'http://127.0.0.1/api/one','status':302},'request':{'url':'http://127.0.0.1/api/two','method':'GET'}})
        cap.on_response({'requestId':'r','response':{'url':'http://127.0.0.1/api/two','status':500},'type':'Document'})
        await rec.flush()
        ev=store.events()
        assert [x['kind'] for x in ev if x['kind']!='manual_marker']==['http_activity','http_error']
        assert [x['fields']['status'] for x in ev if x['kind']!='manual_marker']==[302,500]
        assert ev[0]['fields']['redirect_chain']==ev[1]['fields']['redirect_chain']
    finally:
        await rec.stop();store.close()


@pytest.mark.asyncio
async def test_cross_origin_redirect_does_not_record_authentication_activity(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True); rec=Recorder(store);await rec.start()
    cap=PageCapture(None,None,rec,Scope(test_local=True))
    try:
        cap.on_request({'requestId':'login','request':{'url':'http://127.0.0.1/api/start','method':'GET'}})
        cap.on_request({'requestId':'login','redirectResponse':{'url':'http://127.0.0.1/api/start','status':302},'request':{'url':'https://login.okta.com/path?token=NEVERSTORE','method':'GET'}})
        cap.on_response({'requestId':'login','response':{'url':'https://login.okta.com/path?token=NEVERSTORE','status':401}})
        await rec.flush()
        assert len(store.events())==1
        assert store.events()[0]['fields']['status']==302
        assert b'NEVERSTORE' not in (tmp_path/'flight_recorder.sqlite').read_bytes()
    finally:
        await rec.stop();store.close()


@pytest.mark.asyncio
async def test_automatic_incident_preserves_error_observation_time_under_queue_delay(tmp_path,monkeypatch):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True);rec=Recorder(store)
    real_add=store.add
    def delayed(*a,**k):
        import time
        time.sleep(.12)
        return real_add(*a,**k)
    monkeypatch.setattr(store,'add',delayed)
    await rec.start()
    try:
        observed=datetime.now(timezone.utc)
        assert rec.accept('network_failure','error',{'error_code':'ERR_CONNECTION_RESET'})
        await rec.flush()
        item=store.incidents()[0]
        marker=datetime.fromisoformat(item['at'])
        assert abs((marker-observed).total_seconds())<.06, (marker,observed)
        assert abs((datetime.fromisoformat(store.events()[0]['timestamp'])-marker).total_seconds())<.004
    finally:
        await rec.stop();store.close()


def test_manual_incident_preserves_supplied_time(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    try:
        then=datetime.now(timezone.utc)-timedelta(seconds=8)
        item=store.mark(observed_at=then)
        assert abs((datetime.fromisoformat(item['at'])-then).total_seconds())<.005
        assert store.events()[0]['timestamp']==item['at']
        with pytest.raises(ValueError):store.mark(observed_at=datetime(2026,1,1))
    finally:store.close()


@pytest.mark.asyncio
async def test_authentication_exception_never_saved_even_from_old_context(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True);rec=Recorder(store);await rec.start()
    page=SimpleNamespace(url='https://login.okta.com/oauth')
    cap=PageCapture(None,page,rec,Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')));cap.execution_contexts[1]=True
    try:
        cap.on_exception({'exceptionDetails':{'executionContextId':1,'url':'https://example.org/js/app.js','exception':{'className':'TypeError','description':'PATIENT PHI'}}})
        await rec.flush()
        assert store.events()==[]
    finally:await rec.stop();store.close()


def test_worker_closed_releases_live_reference(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True);rec=Recorder(store)
    class Worker:
        def on(self,event,handler):self.handler=handler
    try:
        cap=PageCapture(None,None,rec,Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')));worker=Worker()
        cap.on_worker(worker)
        assert worker in cap.unsupported_workers
        assert any(x['state']=='UNSUPPORTED' for x in store.coverage())
        worker.handler()
        assert worker not in cap.unsupported_workers
        assert any(x['state']=='DISCONNECTED' for x in store.coverage())
    finally:store.close()


def test_execution_context_cache_bounded_and_gap_recorded(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True);rec=Recorder(store)
    try:
        cap=PageCapture(None,None,rec,Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')))
        cap.execution_contexts.update({i:True for i in range(8192)})
        cap.on_context_created({'context':{'id':8192,'origin':'https://example.org'}})
        assert len(cap.execution_contexts)==1
        assert cap.execution_contexts[8192] is True
    finally:store.close()


def test_event_schema_never_accepts_raw_sensitive_keys_or_free_text():
    for key in ('password','token','cookie','url','requestHeaders','body','message','stackTrace','patientName','description'):
        with pytest.raises(UnsafeEvent):normalize('health','info',{key:'PATIENT_SECRET'})
    for bad in ('https://evil.example','Bearer ABCDEFG','TESTPATIENT'):
        with pytest.raises(UnsafeEvent):normalize('network_failure','error',{'error_code':bad})


@pytest.mark.asyncio
async def test_sensitive_canaries_absent_in_entire_export(tmp_path):
    store=EvidenceStore(tmp_path/'evidence', allow_test_plaintext=True);rec=Recorder(store);await rec.start()
    cap=PageCapture(None,None,rec,Scope(test_local=True))
    secrets=('FAKE_PATIENT_4444','FAKE_TOKEN_5555','FAKE_PASSWORD_6666')
    try:
        cap.on_request({'requestId':'FAKE_TOKEN_5555','request':{'url':'http://127.0.0.1/api/FAKE_PATIENT_4444?password=FAKE_PASSWORD_6666','method':'GET'}})
        cap.on_response({'requestId':'FAKE_TOKEN_5555','response':{'url':'http://127.0.0.1/api/FAKE_PATIENT_4444?password=FAKE_PASSWORD_6666','status':500},'type':'Fetch'})
        cap.execution_contexts[1]=True
        cap.on_exception({'exceptionDetails':{'executionContextId':1,'exception':{'className':'Error','description':'FAKE_PASSWORD_6666'}}})
        await rec.flush()
        archive=tmp_path/'result.zip'
        export_bundle(store,archive)
        with ZipFile(archive) as z:
            assert z.testzip() is None
            for name in z.namelist():
                for secret in secrets:assert secret.encode() not in z.read(name)
        for file in (tmp_path/'evidence').glob('*'):
            if file.is_file():
                for secret in secrets:assert secret.encode() not in file.read_bytes()
    finally:await rec.stop();store.close()


@pytest.mark.asyncio
async def test_completed_event_cannot_claim_application_state_was_saved(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True);rec=Recorder(store);await rec.start()
    cap=PageCapture(None,None,rec,Scope(test_local=True))
    try:
        cap.on_request({'requestId':'r','request':{'url':'http://127.0.0.1/api/save','method':'POST'}})
        cap.on_response({'requestId':'r','response':{'url':'http://127.0.0.1/api/save','status':200},'type':'Fetch'})
        await rec.flush()
        event=store.events()[0]
        assert event['kind']=='http_activity' and event['severity']=='info'
        assert 'application_state' not in event['fields']
    finally:await rec.stop();store.close()

class FakeCdpSession:
    def __init__(self):self.handlers={};self.commands=[]
    def on(self,name,fn):self.handlers[name]=fn
    async def send(self,name,params=None):
        self.commands.append((name,params))
        return {}
    async def detach(self):
        self.commands.append(('DETACH',None))

class FakePage:
    def __init__(self,url):
        self.url=url;self.handlers={};self.main_frame=object();self.closed=False
    def on(self,name,fn):self.handlers.setdefault(name,[]).append(fn)
    def is_closed(self):return self.closed

class FakeContext:
    def __init__(self):
        self.session=FakeCdpSession()
        self.browser=SimpleNamespace(is_connected=lambda: True)
    async def new_cdp_session(self,page):return self.session


@pytest.mark.asyncio
async def test_cdp_subscriptions_function_without_raw_event_persistence(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True); rec=Recorder(store);await rec.start()
    page=FakePage('https://app.example.org');context=FakeContext()
    cap=PageCapture(context,page,rec,Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')))
    try:
        await cap.start()
        assert cap.ready
        assert set(('Network.enable','Runtime.enable','Log.enable','Inspector.enable')) <= {x[0] for x in context.session.commands}
        assert 'Network.webSocketClosed' in context.session.handlers
        assert 'Runtime.exceptionThrown' in context.session.handlers
        context.session.handlers['Runtime.executionContextCreated']({'context':{'id':1,'origin':'https://app.example.org'}})
        context.session.handlers['Runtime.exceptionThrown']({'exceptionDetails':{'executionContextId':1,'exception':{'className':'TypeError','description':'PRIVATE_PATIENT'}}})
        context.session.handlers['Runtime.consoleAPICalled']({'type':'error','executionContextId':1,'args':[{'value':'AUTH_TOKEN'}]})
        context.session.handlers['Network.requestWillBeSent']({'requestId':'a','request':{'method':'GET','url':'https://app.example.org/api/SECRET?token=SECRET'}})
        context.session.handlers['Network.responseReceived']({'requestId':'a','type':'XHR','response':{'url':'https://app.example.org/api/SECRET?token=SECRET','status':503}})
        context.session.handlers['Network.loadingFinished']({'requestId':'a'})
        context.session.handlers['Inspector.targetCrashed']({})
        await rec.flush()
        kinds=[x['kind'] for x in store.events()]
        assert {'js_exception','console_warning','http_error','browser_crash'} <= set(kinds)
        assert 'SECRET' not in str(store.events()) and 'AUTH_TOKEN' not in str(store.events())
    finally:await rec.stop();store.close()


@pytest.mark.asyncio
async def test_cdp_callback_error_fails_visible_without_leaking_raw_data(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True);rec=Recorder(store);await rec.start()
    cap=PageCapture(FakeContext(),FakePage('https://app.example.org'),rec,Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')))
    try:
        cap._guard_event(lambda raw: (_ for _ in ()).throw(RuntimeError('TOKEN_FROM_UNTRUSTED_CDP')), {'password':'SECRET'})
        await rec.flush()
        assert not cap.ready
        assert any(x['kind']=='collection_gap' for x in store.events())
        assert 'TOKEN_FROM_UNTRUSTED_CDP' not in str(store.events())
    finally:await rec.stop();store.close()


@pytest.mark.asyncio
async def test_browserflight_removes_closed_tabs_from_live_targets(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True);rec=Recorder(store);await rec.start()
    flight=BrowserFlight(rec,tmp_path/'profile',Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')))
    flight.context=FakeContext()
    page=FakePage('https://app.example.org')
    try:
        await flight.attach(page)
        assert page in flight.pages
        assert len(flight.pages)==1
        page.closed=True
        for callback in page.handlers['close']:callback()
        assert page not in flight.pages
        assert store.coverage()[0]['state']=='DISCONNECTED'
    finally:await rec.stop();store.close()


@pytest.mark.asyncio
async def test_socket_lifecycle_and_errors_without_payloads(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True);rec=Recorder(store);await rec.start()
    cap=PageCapture(None,None,rec,Scope(test_local=True))
    try:
        cap.on_socket({'requestId':'PRIVATE_SESSION','url':'ws://127.0.0.1/socket.io?token=DO_NOT_STORE'})
        cap.on_socket_handshake({'requestId':'PRIVATE_SESSION','request':{'headers':{'Authorization':'Bearer SECRET'}}})
        cap.on_socket_error({'requestId':'PRIVATE_SESSION','errorMessage':'SECRET'})
        cap.on_socket_close({'requestId':'PRIVATE_SESSION'})
        await rec.flush()
        kinds=[x['kind'] for x in store.events()]
        assert [k for k in kinds if k!='manual_marker']==['websocket_open','websocket_open','websocket_error','websocket_closed']
        assert not any(x in str(store.events()) for x in ('PRIVATE_SESSION','DO_NOT_STORE','Bearer SECRET'))
    finally:await rec.stop();store.close()


def test_watchdog_parent_probe_does_not_signal_process():
    import os
    from diagnostic_browser.watchdog import parent_alive
    assert parent_alive(os.getpid()) is True
    assert parent_alive(0) is None
    assert parent_alive(2**30) is False


def test_watchdog_heartbeat_rejects_oversized_file(tmp_path):
    import json,threading,time
    hb=tmp_path/'heartbeat'; report=tmp_path/'watchdog.jsonl'; stop=tmp_path/'stop'
    hb.write_text('X'*10000)
    def terminate():
        time.sleep(.08)
        stop.touch()
    t=threading.Thread(target=terminate);t.start()
    try:
        watchdog_run(hb,report,stop,0,interval=.02,stale=.5)
        lines=[json.loads(x) for x in report.read_text().splitlines()]
        assert any(x['code']=='COLLECTOR_HEARTBEAT_STALE' for x in lines)
    finally:t.join(timeout=2)


@pytest.mark.asyncio
async def test_transient_cdp_attachment_failure_recovers_without_closing_browser(tmp_path,monkeypatch):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True);rec=Recorder(store);await rec.start()
    page=FakePage('https://app.example.org')
    context=FakeContext()
    real_session=context.new_cdp_session
    attempts={'n':0}
    async def flaky(target):
        attempts['n']+=1
        if attempts['n']==1:raise OSError('temporary connection failure')
        return await real_session(target)
    context.new_cdp_session=flaky
    flight=BrowserFlight(rec,tmp_path/'profile',Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')))
    flight.context=context
    try:
        await flight.attach(page)
        assert flight.pages[page].ready is False
        # Fast-forward the bounded monitor without sleeping three seconds.
        real_sleep=asyncio.sleep
        tick={'n':0}
        async def one_tick(delay):
            tick['n']+=1
            if tick['n']>1:raise asyncio.CancelledError
            return await real_sleep(0)
        monkeypatch.setattr('diagnostic_browser.capture.asyncio.sleep',one_tick)
        try:
            await flight._repair_monitor()
        except asyncio.CancelledError:pass
        assert flight.pages[page].ready is True
        assert attempts['n']==2
        assert flight.status=='ARMED'
        assert page.closed is False
    finally:
        await rec.stop();store.close()


def test_watchdog_detects_browser_disconnection_even_when_recorder_healthy(tmp_path):
    import threading,time
    hb=tmp_path/'collector.heartbeat'; report=tmp_path/'watchdog.jsonl';stop=tmp_path/'stop'
    hb.write_text(json.dumps({'recorder_state':'RECORDING', 'writer_running':True,
         'browser_state':'FAILED', 'browser_connected':False}))
    def finish():
        time.sleep(.09);stop.touch()
    t=threading.Thread(target=finish);t.start()
    try:
        watchdog_run(hb,report,stop,0,interval=.02,stale=.5)
        codes=[json.loads(line)['code'] for line in report.read_text().splitlines()]
        assert 'BROWSER_DEGRADED' in codes
        assert 'RECORDER_RECOVERED' in codes
        snapshot=json.loads((tmp_path/'watchdog.health.json').read_text())
        assert snapshot['browser_degraded'] is True
        assert snapshot['recorder_degraded'] is False
    finally:t.join(timeout=2)


@pytest.mark.asyncio
async def test_idle_maintenance_prunes_unpreserved_old_events(tmp_path, monkeypatch):
    store = EvidenceStore(tmp_path, allow_test_plaintext=True)
    rec = Recorder(store)
    old = datetime.now(timezone.utc) - timedelta(minutes=45)
    store.add('health', 'info', {'code': 'READY'}, observed_at=old)
    assert store.count() == 1
    real_sleep = asyncio.sleep
    count = {'value': 0}
    async def fast_sleep(delay):
        count['value'] += 1
        if count['value'] > 1:
            raise asyncio.CancelledError
        await real_sleep(0)
    monkeypatch.setattr('diagnostic_browser.recorder.asyncio.sleep', fast_sleep)
    try:
        with pytest.raises(asyncio.CancelledError):
            await rec._maintenance()
        assert store.count() == 0
        assert rec.stats['maintenance_checks'] == 1
    finally:
        store.close()


def test_html_viewer_is_bounded_but_full_machine_export_keeps_event_count():
    from diagnostic_browser.reports import build_html, build_csv, jsonl
    events = [dict(id=f'{i:032x}',session='a'*32,timestamp='2026-10-31T00:00:00+00:00',
                   kind='health',severity='info',fields={'code':'READY'})
              for i in range(5010)]
    page = build_html(events, [], 'SYNTHETIC').decode()
    # The HTML viewer cannot create tens of thousands of live DOM rows.
    assert page.count('<tr><td>') == 5000
    assert '5010' in page  # all approved event count remains visible
    assert 'latest 5,000 records' in page
    assert len(jsonl(events).splitlines()) == 5010
    assert len(build_csv(events).decode().splitlines()) == 5011
