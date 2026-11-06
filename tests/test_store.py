import os
import sqlite3
import pytest
from diagnostic_browser.store import EvidenceStore
from diagnostic_browser.recorder import Recorder
from diagnostic_browser.reports import export_bundle
from pathlib import Path
from zipfile import ZipFile

@pytest.fixture
def store(tmp_path):
    s=EvidenceStore(tmp_path, allow_test_plaintext=True)
    yield s
    s.close()

def test_encrypted_and_crash_reopen(store,tmp_path):
    x=store.add('http_error','error',{'status':500,'method':'GET','route':'api'})
    raw=(tmp_path/'flight_recorder.sqlite').read_bytes()
    assert store.db.execute("SELECT id FROM events").fetchone()[0] == x["id"]  # SQLite metadata is indexed
    assert b'"kind":"http_error"' not in raw
    assert store.events()[0]==x
    store.close()
    reopened=EvidenceStore(tmp_path, allow_test_plaintext=True)
    assert reopened.events()[0]==x
    reopened.close()

def test_key_loss_refuses_recovery(tmp_path):
    s=EvidenceStore(tmp_path, allow_test_plaintext=True);s.add('health','info',{'target':'collector','code':'READY'});s.close()
    (tmp_path/'evidence.key').write_bytes(b'broken')
    with pytest.raises(OSError):EvidenceStore(tmp_path, allow_test_plaintext=True)

def test_incident_preservation(store):
    x=store.mark()
    assert store.incidents()[0]['id']==x['id']
    assert store.events()[0]['fields']['incident_id']==x['id']

def test_export_valid_zip(store,tmp_path):
    store.add('http_error','error',{'method':'POST','status':500,'route':'api'})
    path=tmp_path/'bundle.zip'
    result=export_bundle(store,path)
    assert result['event_count']==1
    with ZipFile(path) as z:
        assert z.testzip() is None
        assert b'http_error' in z.read('03_Full_Event_Timeline.jsonl')
        assert z.read('01_Engineering_Report.pdf').startswith(b'%PDF')
        assert b'Content-Security-Policy' in z.read('02_Offline_Interactive_Report.html')
        assert b'http_error' in z.read('04_Full_Event_Timeline.csv')

@pytest.mark.asyncio
async def test_queue_and_writer(store):
    r=Recorder(store,max_queue=2)
    await r.start()
    assert r.accept('health','info',{'target':'collector','code':'READY'})
    assert not r.accept('health','info',{'token':'secret'})
    await r.flush()
    assert r.stats['committed']==1
    assert r.stats['privacy_rejected']==1
    await r.stop()
