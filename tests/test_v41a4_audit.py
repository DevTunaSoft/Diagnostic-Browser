"""Independent review: chronology, privacy scope and verification under load."""
import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4
import json
import pytest
from httpx import ASGITransport, AsyncClient
from diagnostic_browser.store import EvidenceStore
from diagnostic_browser.recorder import Recorder
from diagnostic_browser.capture import PageCapture
from diagnostic_browser.policy import Scope
from diagnostic_browser.server import Dashboard

@pytest.mark.asyncio
async def test_event_timestamp_is_observation_time_not_delayed_commit(tmp_path, monkeypatch):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    recorder=Recorder(store)
    original=store.add
    async def idle_hold():
        await asyncio.sleep(0.15)
    monkeypatch.setattr(asyncio, 'sleep', idle_hold) if False else None
    def delayed(*args,**kwargs):
        import time
        time.sleep(0.12)
        return original(*args,**kwargs)
    monkeypatch.setattr(store, 'add', delayed)
    await recorder.start()
    try:
        before=datetime.now(timezone.utc)
        assert recorder.accept('health','info',{'code':'READY'})
        await recorder.flush()
        after=datetime.now(timezone.utc)
        e=store.events()[0]
        observed=datetime.fromisoformat(e['timestamp'])
        assert before - timedelta(seconds=.1) <= observed <= before + timedelta(seconds=.07)
        assert (after-observed).total_seconds() >= .10
    finally:
        await recorder.stop();store.close()

@pytest.mark.asyncio
async def test_manual_marker_drains_previously_accepted_event(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    recorder=Recorder(store)
    await recorder.start()
    dashboard=Dashboard(store,recorder,tmp_path)
    try:
        async with AsyncClient(transport=ASGITransport(app=dashboard.app),base_url='http://127.0.0.1:19040') as client:
            await client.post('/api/login',json={'code':dashboard.login_code})
            csrf=(await client.get('/api/session')).json()['csrf']
            assert recorder.accept('health','info',{'code':'READY'})
            r=await client.post('/api/incidents',headers={'X-CSRF-Token':csrf})
            assert r.status_code==200
            assert [e['kind'] for e in store.events()]==['health','manual_marker']
    finally:
        await recorder.stop();store.close()

@pytest.mark.asyncio
async def test_exact_selftest_with_busy_recorder_more_than_ten_new_events(tmp_path,monkeypatch):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    recorder=Recorder(store)
    await recorder.start()
    dashboard=Dashboard(store,recorder,tmp_path)
    original=recorder.flush
    async def busy_flush(*args,**kwargs):
        for n in range(30):
            recorder.accept('health','info',{'count':n,'code':'READY'})
        await original(*args,**kwargs)
    monkeypatch.setattr(recorder, 'flush', busy_flush)
    try:
        async with AsyncClient(transport=ASGITransport(app=dashboard.app),base_url='http://127.0.0.1:19040') as client:
            await client.post('/api/login',json={'code':dashboard.login_code})
            csrf=(await client.get('/api/session')).json()['csrf']
            out=await client.post('/api/self-test',headers={'X-CSRF-Token':csrf})
            assert out.status_code==200
            assert out.json()['collector_delivery'] is True
            assert out.json()['database_commit_readback'] is True
            assert store.verify_self_test(store.events()[0]['fields']['request_ref'])
    finally:
        await recorder.stop();store.close()

@pytest.mark.asyncio
async def test_scope_excludes_auth_page_even_when_embedded_resource_is_approved(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    recorder=Recorder(store)
    await recorder.start()
    page=SimpleNamespace(url='https://login.okta.com/login')
    page.main_frame=SimpleNamespace(url=page.url)
    cap=PageCapture(None,page,recorder,Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')))
    try:
        cap.on_request({'requestId':'test','request':{'method':'GET','url':'https://example.org/api?token=SECRET'}})
        cap.on_response({'requestId':'test','response':{'url':'https://example.org/api','status':500},'type':'XHR'})
        cap.on_socket({'requestId':'socket','url':'wss://example.org/socket.io?token=SECRET'})
        cap.on_log({'entry':{'url':'https://example.org/api','level':'error'}})
        await recorder.flush()
        assert store.events()==[]
        assert len(cap.requests)==0
        assert len(cap.sockets)==0
    finally:
        await recorder.stop();store.close()

@pytest.mark.asyncio
async def test_initial_blank_tab_can_capture_authorized_first_request(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True);rec=Recorder(store);await rec.start()
    page=SimpleNamespace(url='about:blank');page.main_frame=SimpleNamespace(url='about:blank')
    cap=PageCapture(None,page,rec,Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')))
    try:
        cap.on_request({'requestId':'first','request':{'url':'https://example.org/api/save','method':'POST'}})
        page.url='https://example.org/'
        cap.on_response({'requestId':'first','type':'XHR','response':{'url':'https://example.org/api/save','status':503}})
        await rec.flush()
        assert [e['fields']['status'] for e in store.events() if e['kind']=='http_error']==[503]
    finally:
        await rec.stop();store.close()

def test_direct_store_observation_time_requires_aware_datetime(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    try:
        with pytest.raises(ValueError):store.add('health','info',{'code':'READY'},observed_at=datetime(2026,1,1))
        with pytest.raises(ValueError):store.add('health','info',{'code':'READY'},observed_at=datetime.now(timezone.utc)-timedelta(days=3))
    finally:store.close()

@pytest.mark.asyncio
async def test_manual_incident_is_possible_after_known_loss(tmp_path, monkeypatch):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True);rec=Recorder(store);await rec.start()
    real_add=store.add
    def fail_health(kind, severity, fields, **kwargs):
        if kind == 'health':
            raise OSError('injected write failure')
        return real_add(kind,severity,fields,**kwargs)
    monkeypatch.setattr(store,'add',fail_health)
    dash=Dashboard(store,rec,tmp_path)
    try:
        assert rec.accept('health','info',{'code':'READY'})
        await rec.flush()
        assert rec.stats['lost_events'] == 1
        async with AsyncClient(transport=ASGITransport(app=dash.app),base_url='http://127.0.0.1:19040') as client:
            await client.post('/api/login',json={'code':dash.login_code})
            csrf=(await client.get('/api/session')).json()['csrf']
            res=await client.post('/api/incidents',headers={'X-CSRF-Token':csrf})
            assert res.status_code == 200
        assert len(store.incidents())==1
        assert sum(x['count'] for x in store.losses()) >= 1
    finally:
        await rec.stop();store.close()

@pytest.mark.asyncio
async def test_initial_navigation_response_before_address_update_is_seen(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True);rec=Recorder(store);await rec.start()
    page=SimpleNamespace(url='about:blank');page.main_frame=SimpleNamespace(url=page.url)
    cap=PageCapture(None,page,rec,Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')))
    try:
        cap.on_request({'requestId':'first','request':{'url':'https://example.org/api/save','method':'POST'}})
        cap.on_response({'requestId':'first','response':{'url':'https://example.org/api/save','status':500},'type':'XHR'})
        await rec.flush()
        assert any(e['kind']=='http_error' and e['fields']['status']==500 for e in store.events())
    finally:
        await rec.stop();store.close()
