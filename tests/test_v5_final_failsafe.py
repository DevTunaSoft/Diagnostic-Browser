"""Security regressions exercised with synthetic local-only data."""
from __future__ import annotations
import asyncio, json, os, threading, time
from pathlib import Path
import pytest
import httpx
from diagnostic_browser.store import EvidenceStore
from diagnostic_browser.recorder import Recorder
from diagnostic_browser.server import Dashboard
from diagnostic_browser.watchdog import run as watchdog_run


def test_watchdog_rejects_unknown_component_states(tmp_path):
    heartbeat=tmp_path/'collector.heartbeat'
    heartbeat.write_text(json.dumps({'recorder_state':'TOTALLY_FINE',
           'writer_running':True, 'browser_state':'ALL_GOOD',
           'browser_connected':True}))
    report=tmp_path/'watchdog.jsonl';stop=tmp_path/'stop'
    thread=threading.Thread(target=watchdog_run,
          args=(heartbeat,report,stop,0,0.025,1),daemon=True)
    thread.start()
    try:
        out=tmp_path/'watchdog.health.json'
        deadline=time.monotonic()+3
        while not out.exists() and time.monotonic()<deadline:time.sleep(0.01)
        assert out.exists()
        state=json.loads(out.read_text())
        assert state['recorder_degraded'] is None
        assert state['browser_degraded'] is None
    finally:
        stop.touch();thread.join(timeout=3)


@pytest.mark.asyncio
async def test_chunked_requests_rejected_at_64k_before_allocation(tmp_path):
    store=EvidenceStore(tmp_path,allow_test_plaintext=True)
    recorder=Recorder(store)
    await recorder.start()
    app=Dashboard(store,recorder,tmp_path).app
    generated=[]
    async def huge_chunked_body():
        generated.append(1)
        yield b'x'*32768
        generated.append(1)
        yield b'x'*32768
        generated.append(1)
        yield b'x'*131072
        generated.append(1)
        yield b'extra chunk must never be read'
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://127.0.0.1:18731') as client:
            response=await client.post('/api/login',content=huge_chunked_body(),
                           headers={'content-type':'application/json'})
        assert response.status_code==413
        assert len(generated)==3  # stopped on first over-limit chunk
    finally:
        await recorder.stop();store.close()
