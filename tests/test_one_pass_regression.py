"""Independent one-pass audit tests for risks previously omitted by coverage."""
from __future__ import annotations
import asyncio
import json
import time
from types import SimpleNamespace
from zipfile import ZipFile
import pytest
from httpx import ASGITransport, AsyncClient
from diagnostic_browser.capture import PageCapture
from diagnostic_browser.store import EvidenceStore
from diagnostic_browser.recorder import Recorder
from diagnostic_browser.policy import Scope
from diagnostic_browser.server import Dashboard
from diagnostic_browser.reports import export_bundle


@pytest.mark.asyncio
async def test_same_scope_navigation_does_not_erase_outstanding_http_errors(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    recorder=Recorder(store)
    await recorder.start()
    page=SimpleNamespace(url='https://example.org/dispatch')
    frame=SimpleNamespace(url=page.url)
    page.main_frame=frame
    capture=PageCapture(None,page,recorder,Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')))
    try:
        capture.on_request({'requestId':'request-one','request':{'url':'https://example.org/api/orders?token=canaryA','method':'POST'}})
        frame.url=page.url='https://example.org/other'
        capture.on_navigation(frame)
        capture.on_response({'requestId':'request-one','response':{'url':'https://example.org/api/orders','status':500},'type':'XHR'})
        await recorder.flush()
        assert any(e['kind']=='http_error' and e['fields']['status']==500 for e in store.events())
        assert 'canaryA' not in str(store.events())
    finally:
        await recorder.stop();store.close()


@pytest.mark.asyncio
async def test_navigation_to_auth_provider_clears_pending_and_excludes_stale_context(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    recorder=Recorder(store)
    await recorder.start()
    page=SimpleNamespace(url='https://example.org/')
    frame=SimpleNamespace(url=page.url)
    page.main_frame=frame
    capture=PageCapture(None,page,recorder,Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')))
    try:
        capture.execution_contexts[12]=True
        capture.on_request({'requestId':'req','request':{'url':'https://example.org/api', 'method':'GET'}})
        page.url=frame.url='https://login.okta.com/auth?access_token=CANARY'
        capture.on_exception({'exceptionDetails':{'executionContextId':12,'exception':{'className':'TypeError'},'lineNumber':2}})
        capture.on_console({'executionContextId':12,'type':'error'})
        capture.on_navigation(frame)
        capture.on_response({'requestId':'req','response':{'url':'https://example.org/api','status':500},'type':'XHR'})
        await recorder.flush()
        assert not any(x['kind'] in ('js_exception','console_warning','http_error') for x in store.events())
        assert store.coverage()[0]['state']=='EXCLUDED'
    finally:
        await recorder.stop();store.close()


def test_readonly_evidence_connection_is_not_a_writer_and_has_repeatable_snapshot(tmp_path):
    main=EvidenceStore(tmp_path, allow_test_plaintext=True)
    try:
        main.add('health','info',{'code':'READY'})
        reader=EvidenceStore(tmp_path,read_only=True,allow_test_plaintext=True)
        try:
            reader.db.execute('BEGIN')
            reader.db.execute('SELECT COUNT(*) FROM events').fetchone()
            main.add('health','warning',{'code':'READY'})
            assert len(reader.events())==1
            assert len(main.events())==2
            with pytest.raises(Exception): reader.add('health','info',{'code':'READY'})
            reader.db.execute('ROLLBACK')
            assert len(reader.events())==2
        finally:reader.close()
    finally:main.close()


@pytest.mark.asyncio
async def test_export_is_backgrounded_and_allows_live_capture(tmp_path,monkeypatch):
    from diagnostic_browser import server as server_module
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    recorder=Recorder(store)
    await recorder.start()
    dashboard=Dashboard(store,recorder,tmp_path)
    actual=server_module.export_bundle
    began=__import__('threading').Event()
    def slow_export(*args,**kwargs):
        began.set()
        time.sleep(0.15)
        return actual(*args,**kwargs)
    monkeypatch.setattr(server_module,'export_bundle',slow_export)
    try:
        async with AsyncClient(transport=ASGITransport(app=dashboard.app),base_url='http://127.0.0.1:18731') as client:
            assert (await client.post('/api/login',json={'code':dashboard.login_code})).status_code==200
            csrf=(await client.get('/api/session')).json()['csrf']
            task=asyncio.create_task(client.post('/api/export',headers={'X-CSRF-Token':csrf},json={'preset':'engineering'}))
            for _ in range(100):
                if began.is_set():break
                await asyncio.sleep(0.002)
            assert began.is_set()
            assert recorder.accept('health','info',{'code':'READY'})
            await recorder.flush(timeout=5)
            res=await task
            assert res.status_code==200,res.text
            zip_path=tmp_path/'exports'/res.json()['filename']
            with ZipFile(zip_path) as z:
                assert z.testzip() is None
                assert '08_SHA256_Manifest.json' in z.namelist()
    finally:
        await recorder.stop()
        store.close()

@pytest.mark.asyncio
async def test_export_archive_names_are_unique_and_immutable(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True)
    rec=Recorder(store)
    await rec.start()
    dashboard=Dashboard(store,rec,tmp_path)
    try:
        async with AsyncClient(transport=ASGITransport(app=dashboard.app),base_url='http://127.0.0.1:18731') as client:
            assert (await client.post('/api/login',json={'code':dashboard.login_code})).status_code==200
            csrf=(await client.get('/api/session')).json()['csrf']
            headers={'X-CSRF-Token':csrf}
            first=(await client.post('/api/export',headers=headers,json={'preset':'engineering'})).json()
            rec.accept('health','info',{'code':'READY'})
            await rec.flush()
            second=(await client.post('/api/export',headers=headers,json={'preset':'engineering'})).json()
            assert first['filename']!=second['filename']
            assert first['sha256']!=second['sha256']
            old=await client.get('/api/export/file/'+first['filename'])
            new=await client.get('/api/export/file/'+second['filename'])
            assert old.status_code==200 and new.status_code==200
            assert old.content!=new.content
            assert (await client.get('/api/export/engineering')).status_code==404
            assert (await client.get('/api/export/file/../../evidence.key')).status_code != 200
    finally:
        await rec.stop()
        store.close()
