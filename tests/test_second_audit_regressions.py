"""Additional audit: real defects missed by the original V4.1 automated tests."""
from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest
from httpx import AsyncClient, ASGITransport

from diagnostic_browser.capture import PageCapture
from diagnostic_browser.policy import Scope
from diagnostic_browser.recorder import Recorder
from diagnostic_browser.request_ledger import RequestLedger
from diagnostic_browser.server import Dashboard
from diagnostic_browser.store import EvidenceStore


def test_navigation_resets_request_cache_and_updates_coverage(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    try:
        page=SimpleNamespace()
        frame=SimpleNamespace(url='https://example.org/dispatch')
        page.main_frame=frame
        capture=PageCapture(None,page,Recorder(store),Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')))
        capture.execution_contexts[23]=True
        capture.requests.begin({'requestId':'prior', 'request':{
            'url':'https://example.org/api/item?patient=SECRET', 'method':'GET'}})
        capture.sockets['s']=True
        assert capture.requests.get('prior') is not None
        capture.on_navigation(frame)  # V4.1 crashed here: RequestLedger.clear() missing
        # The pending same-scope API request must survive navigation so late
        # HTTP failures are not silently lost.
        assert len(capture.requests)==1
        assert not capture.execution_contexts
        assert capture.sockets
        assert store.coverage()[0]['state']=='ACTIVE'
        frame.url='https://login.okta.com/redirect?token=SECRET'
        capture.on_navigation(frame)
        assert store.coverage()[0]['state']=='EXCLUDED'
        assert len(capture.requests)==0
        assert not capture.sockets
    finally:store.close()


def test_invalid_http_method_does_not_crash_collector():
    ledger=RequestLedger(Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')))
    _,hop=ledger.begin({'requestId':'a','request':{
        'url':'https://example.org/api','method':['POST','SECRET']}})
    assert hop is not None and not hop.authorized
    assert hop.method=='GET'  # sanitized fallback exists only in an unauthorized hop


def test_mark_is_transactional_when_marker_write_fails(tmp_path,monkeypatch):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    try:
        def fail(*args,**kwargs):raise OSError('injected disk write failure')
        monkeypatch.setattr(store,'add',fail)
        with pytest.raises(OSError):store.mark()
        assert store.incidents()==[]  # previously an orphan incident survived
    finally:store.close()


def test_recent_events_bounded_order_complete_export_unaffected(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    try:
        for n in range(250):
            store.add('health','info',{'code':'READY','count':n})
        last=store.recent_events(10)
        assert len(last)==10 and [x['fields']['count'] for x in last]==list(range(240,250))
        assert len(store.events())==250
        with pytest.raises(ValueError):store.recent_events(1001)
    finally:store.close()


@pytest.mark.asyncio
async def test_dashboard_recent_events_query_is_bounded(tmp_path,monkeypatch):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    recorder=Recorder(store)
    dash=Dashboard(store,recorder,tmp_path)
    for i in range(225):store.add('health','info',{'count':i})
    async with AsyncClient(transport=ASGITransport(app=dash.app),base_url='http://127.0.0.1:18731') as client:
        assert (await client.post('/api/login',json={'code':dash.login_code})).status_code==200
        result=await client.get('/api/events?limit=5')
        assert result.status_code==200
        assert [x['fields']['count'] for x in result.json()]==list(range(220,225))
    store.close()


def test_existing_pre_migration_baseline_schema_is_migrated(tmp_path):
    db=sqlite3.connect(tmp_path/'flight_recorder.sqlite')
    db.execute('CREATE TABLE baselines(id TEXT PRIMARY KEY,at TEXT NOT NULL,ciphertext BLOB NOT NULL)')
    db.commit();db.close()
    # Historical database without key deliberately refuses to generate replacement.
    with pytest.raises(OSError,match='key missing'):EvidenceStore(tmp_path, allow_test_plaintext=True)
    # Create a fresh key in an empty directory, then replace its baseline table
    # with the old table shape to reproduce an actual upgrade scenario.
    other=tmp_path/'old';other.mkdir()
    first=EvidenceStore(other, allow_test_plaintext=True);first.close()
    conn=sqlite3.connect(other/'flight_recorder.sqlite')
    conn.execute('DROP TABLE baselines')
    conn.execute('CREATE TABLE baselines(id TEXT PRIMARY KEY,at TEXT NOT NULL,ciphertext BLOB NOT NULL)')
    conn.commit();conn.close()
    reopened=EvidenceStore(other, allow_test_plaintext=True)
    assert 'end_seq' in [r[1] for r in reopened.db.execute('PRAGMA table_info(baselines)')]
    reopened.close()


def test_regression_ignores_baseline_history_in_current_sample(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    try:
        store.add('js_exception','error',{'error_class':'TypeError'})
        store.save_baseline()
        # Before the fix this was 'PERSISTENT' merely because we kept the old event.
        assert store.compare_baseline()['differences'][0]['classification']=='NOT_OBSERVED'
        store.add('js_exception','error',{'error_class':'TypeError'})
        assert store.compare_baseline()['differences'][0]['classification']=='PERSISTENT'
    finally:store.close()

@pytest.mark.asyncio
async def test_malformed_protocol_event_degrades_instead_of_silent_callback_crash(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    recorder=Recorder(store)
    await recorder.start()
    try:
        capture=PageCapture(None,None,recorder,Scope(test_local=True))
        capture.ready=True
        capture.on_request({'requestId':'1','request':{
            'url':'http://127.0.0.1/api','method':'GET'}})
        # A malformed response used to explode inside the CDP event emitter.
        capture._guard_event(capture.on_response, {
            'requestId':'1','response':['unexpected','response']})
        await recorder.flush()
        assert not capture.ready
        assert store.coverage()[0]['state']=='FAILING'
        assert any(e['kind']=='collection_gap' and e['fields']['reason']=='failed'
                   for e in store.events())
    finally:
        await recorder.stop();store.close()

@pytest.mark.asyncio
async def test_self_test_never_reuses_an_old_successful_synthetic_event(tmp_path,monkeypatch):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    recorder=Recorder(store)
    await recorder.start()
    try:
        dash=Dashboard(store,recorder,tmp_path)
        async with AsyncClient(transport=ASGITransport(app=dash.app),base_url='http://127.0.0.1:18731') as client:
            assert (await client.post('/api/login',json={'code':dash.login_code})).status_code==200
            csrf=(await client.get('/api/session')).json()['csrf']
            headers={'X-CSRF-Token':csrf}
            first=(await client.post('/api/self-test',headers=headers)).json()
            assert first['collector_delivery']
            original=store.add
            def selective_failure(kind, severity, fields):
                if kind=='self_test':
                    raise OSError('synthetic test write failure')
                return original(kind,severity,fields)
            monkeypatch.setattr(store,'add',selective_failure)
            second=(await client.post('/api/self-test',headers=headers)).json()
            assert second['collector_delivery'] is False
            assert second['database_commit_readback'] is False
    finally:
        await recorder.stop();store.close()
