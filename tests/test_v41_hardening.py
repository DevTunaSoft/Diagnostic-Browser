"""V4.1 failure-mode and privacy regression tests; no production access required."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from zipfile import ZipFile

import pytest

from diagnostic_browser.capture import PageCapture
from diagnostic_browser.policy import Scope
from diagnostic_browser.recorder import Recorder
from diagnostic_browser.request_ledger import RequestLedger
from diagnostic_browser.reports import export_bundle
from diagnostic_browser.server import Dashboard
from diagnostic_browser.store import EvidenceStore
from diagnostic_browser.watchdog import run as watchdog_run


def test_redirect_reuses_raw_id_but_not_exported_request_reference(tmp_path):
    ledger = RequestLedger(Scope(test_local=True))
    old, first = ledger.begin({'requestId':'1', 'request':{
        'url':'http://127.0.0.1:8888/api/item/PRIVATE_PATIENT?token=CANARY', 'method':'GET'}})
    assert old is None
    previous, second = ledger.begin({'requestId':'1', 'redirectResponse':{
        'url':'http://127.0.0.1:8888/api/item/PRIVATE_PATIENT', 'status':302},
        'request':{'url':'http://127.0.0.1:8888/api/other?TOKEN=CANARY','method':'GET'}})
    assert previous == first
    assert first.reference != second.reference
    assert first.chain == second.chain
    assert second.hop == 1
    assert 'CANARY' not in str(second)
    assert 'PRIVATE_PATIENT' not in str(second)
    assert ledger.finish('1') == second
    assert ledger.get('1') is None


def test_request_id_reuse_without_redirect_never_merges():
    ledger=RequestLedger(Scope(test_local=True))
    ledger.begin({'requestId':'a','request':{'url':'http://127.0.0.1/api','method':'GET'}})
    first=ledger.get('a')
    ledger.begin({'requestId':'a','request':{'url':'http://127.0.0.1/api','method':'GET'}})
    second=ledger.get('a')
    assert first.chain != second.chain
    assert second.hop == 0


def test_ledger_is_bounded_and_tracks_missing_correlations():
    ledger=RequestLedger(Scope(test_local=True),capacity=2)
    for i in range(3):
        ledger.begin({'requestId':str(i),'request':{
            'url':'http://127.0.0.1/api','method':'GET'}})
    assert len(ledger)==2
    assert ledger.evictions==1
    assert ledger.get('0') is None


@pytest.mark.asyncio
async def test_redirect_and_auth_boundary_with_cdp(tmp_path):
    store=EvidenceStore(tmp_path/'db', allow_test_plaintext=True)
    rec=Recorder(store)
    await rec.start()
    c=PageCapture(None,None,rec,Scope(test_local=True))
    try:
        c.on_request({'requestId':'1','request':{'url':'http://127.0.0.1/api/private/PATIENT_CANARY','method':'GET'}})
        c.on_request({'requestId':'1','redirectResponse':{'url':'http://127.0.0.1/api/private/PATIENT_CANARY','status':302},
                      'request':{'url':'https://example.okta.com/callback?access_token=SECRET_TOKEN','method':'GET'}})
        c.on_response({'requestId':'1','response':{'url':'https://example.okta.com/callback?access_token=SECRET_TOKEN','status':403},'type':'Document'})
        c.on_failed({'requestId':'1','errorText':'net::ERR_FAILED'})
        c.on_request({'requestId':'2','request':{'url':'http://127.0.0.1/api/save?secret=TEST_SECRET','method':'POST'}})
        c.on_response({'requestId':'2','response':{'url':'http://127.0.0.1/api/save?secret=TEST_SECRET','status':500},'type':'XHR'})
        c.on_failed({'requestId':'2','errorText':'net::ERR_CONNECTION_RESET synthetic TEST_SECRET'})
        await rec.flush()
        ev=store.events()
        assert sum(x['kind']=='http_error' for x in ev)==1
        assert sum(x['kind']=='network_failure' for x in ev)==1
        http=next(x for x in ev if x['kind']=='http_error')
        fail=next(x for x in ev if x['kind']=='network_failure')
        assert http['fields']['request_ref']==fail['fields']['request_ref']
        assert 'SECRET_TOKEN' not in str(ev)
        assert 'PATIENT_CANARY' not in str(ev)
        assert 'TEST_SECRET' not in str(ev)
    finally:
        await rec.stop()
        store.close()


@pytest.mark.asyncio
async def test_recover_transient_write_then_export(tmp_path, monkeypatch):
    store=EvidenceStore(tmp_path/'db', allow_test_plaintext=True)
    rec=Recorder(store)
    real_add=store.add
    attempts={'count':0}
    def sometimes_fails(*args,**kwargs):
        attempts['count']+=1
        if attempts['count']<3:
            raise OSError('synthetic storage failure')
        return real_add(*args,**kwargs)
    monkeypatch.setattr(store,'add',sometimes_fails)
    await rec.start()
    try:
        assert rec.accept('health','info',{'code':'READY','target':'collector'})
        await rec.flush(strict=True)
        assert rec.stats['recovered_writes']==1
        assert rec.stats['lost_events']==0
        assert store.count()==1
    finally:
        await rec.stop()
        store.close()


@pytest.mark.asyncio
async def test_permanent_write_failure_is_reported_in_export(tmp_path, monkeypatch):
    store=EvidenceStore(tmp_path/'db', allow_test_plaintext=True)
    rec=Recorder(store)
    original=store.add
    def failed(*args,**kwargs):raise OSError('synthetic disk error')
    monkeypatch.setattr(store,'add',failed)
    await rec.start()
    try:
        assert rec.accept('health','info',{'code':'READY','target':'collector'})
        await rec.flush()  # known loss must not block export of OTHER committed evidence
        assert rec.stats['lost_events']==1
        assert rec.health()['state']=='DEGRADED'
        assert store.losses()[0]['reason']=='WRITE_FAILED'
        with pytest.raises(OSError):await rec.flush(strict=True)
        monkeypatch.setattr(store,'add',original)
        path=tmp_path/'loss.zip'
        export_bundle(store,path)
        with ZipFile(path) as z:
            losses=json.loads(z.read('06A_Evidence_Loss_Ledger.json'))
            manifest=json.loads(z.read('08_SHA256_Manifest.json'))
        assert sum(x['count'] for x in losses)==1
        assert manifest['known_loss_count']==1
    finally:
        await rec.stop()
        store.close()


def test_key_loss_does_not_silently_rotate(tmp_path):
    db=EvidenceStore(tmp_path, allow_test_plaintext=True)
    db.add('health','info',{'target':'collector','code':'READY'})
    db.close()
    (tmp_path/'evidence.key').unlink()
    with pytest.raises(OSError,match='key missing'):
        EvidenceStore(tmp_path, allow_test_plaintext=True)
    assert not (tmp_path/'evidence.key').exists()


def test_watchdog_stale_and_unverified(tmp_path):
    from threading import Thread
    from time import sleep, monotonic
    db=EvidenceStore(tmp_path/'db', allow_test_plaintext=True);rec=Recorder(db)
    dash=Dashboard(db,rec,tmp_path)
    assert dash._watchdog_status()['state']=='UNVERIFIED'
    health=tmp_path/'collector.heartbeat';report=tmp_path/'watchdog.jsonl';stop=tmp_path/'watchdog.stop'
    health.write_text(json.dumps({'recorder_state':'DEGRADED','writer_running':False}))
    thread=Thread(target=watchdog_run,args=(health,report,stop,0,0.05,2.0))
    thread.start()
    try:
        until=monotonic()+4
        while monotonic()<until and dash._watchdog_status()['state']!='DEGRADED':
            sleep(0.025)
        assert dash._watchdog_status()['state']=='DEGRADED'
        health.write_text(json.dumps({'recorder_state':'RECORDING','writer_running':True}))
        until=monotonic()+4
        # A missing browser heartbeat is UNKNOWN, never a healthy state,
        # even when the recorder itself reports recovery.
        while monotonic()<until and dash._watchdog_status()['state']!='UNVERIFIED':
            sleep(0.025)
        assert dash._watchdog_status()['state']=='UNVERIFIED'
    finally:
        stop.touch();thread.join(timeout=3)
        db.close()
    # stale watchdog health is never accepted as current
    file=tmp_path/'watchdog.health.json'
    payload=json.loads(file.read_text())
    payload['at']=(datetime.now(timezone.utc)-timedelta(minutes=5)).isoformat()
    file.write_text(json.dumps(payload))
    assert dash._watchdog_status()['state']=='STALE'
