"""Independent follow-up audit: fail-closed production, health and local API."""
from __future__ import annotations
import asyncio
import json
import os
import threading
import time
import types
import sys
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from diagnostic_browser.store import EvidenceStore
from diagnostic_browser.server import Dashboard
from diagnostic_browser.recorder import Recorder
from diagnostic_browser.watchdog import run as watchdog_run


def test_nonwindows_production_must_not_create_plaintext_key(tmp_path, monkeypatch):
    if os.name == 'nt':
        pytest.skip('Non-Windows regression test')
    # Simulate SQLCipher being importable: the OS key protection still fails shut.
    with monkeypatch.context() as m:
        stub=types.ModuleType('sqlcipher3')
        stub.dbapi2=types.ModuleType('sqlcipher3.dbapi2')
        m.setitem(sys.modules, 'sqlcipher3', stub)
        m.setitem(sys.modules, 'sqlcipher3.dbapi2', stub.dbapi2)
        with pytest.raises(RuntimeError, match='Windows DPAPI'):
            EvidenceStore(tmp_path)
    assert not (tmp_path/'evidence.key').exists()
    assert not (tmp_path/'flight_recorder.sqlite').exists()


def test_watchdog_does_not_claim_unknown_health_is_healthy(tmp_path):
    heartbeat=tmp_path/'collector.heartbeat'
    heartbeat.write_text('not valid JSON', encoding='utf-8')
    report=tmp_path/'watchdog.jsonl';stop=tmp_path/'stop'
    t=threading.Thread(target=watchdog_run,args=(heartbeat,report,stop,0,0.04,0.3),daemon=True)
    t.start()
    try:
        end=time.monotonic()+3
        health=tmp_path/'watchdog.health.json'
        while not health.exists() and time.monotonic()<end:time.sleep(0.01)
        assert health.exists()
        obj=json.loads(health.read_text())
        assert obj['recorder_degraded'] is None
        assert obj['browser_degraded'] is None
    finally:
        stop.touch();t.join(timeout=3)


@pytest.mark.asyncio
async def test_local_dashboard_login_rate_limit_and_body_cap(tmp_path):
    store=EvidenceStore(tmp_path,allow_test_plaintext=True)
    rec=Recorder(store)
    await rec.start()
    dashboard=Dashboard(store,rec,tmp_path)
    try:
        async with AsyncClient(transport=ASGITransport(app=dashboard.app),base_url='http://127.0.0.1:18731') as client:
            for _ in range(5):
                res=await client.post('/api/login',json={'code':'invalid'})
                assert res.status_code==401
            assert (await client.post('/api/login',json={'code':dashboard.login_code})).status_code==429
            assert (await client.post('/api/login',content=b'X'*65537,
                        headers={'Content-Type':'application/json'})).status_code==413
            # Simulate timeout beyond the rate-limit interval; no waiting.
            dashboard.failed_logins.clear()
            assert (await client.post('/api/login',json={'code':dashboard.login_code})).status_code==200
            token=client.cookies.get('diagnostic_session')
            dashboard.session_touched[token]-=8*3600+1
            assert (await client.get('/api/status')).status_code==401
    finally:
        await rec.stop();store.close()
