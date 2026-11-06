"""Live process-level integration: host, collector, watchdog, dashboard and exports.

Uses a protected synthetic data store because production Windows DPAPI/SQLCipher
cannot be validated on this Linux test machine. Does not touch example.
"""
from __future__ import annotations
import asyncio
from pathlib import Path
import shutil
import socket
import time
from types import SimpleNamespace

import httpx
import pytest

from diagnostic_browser import main
from diagnostic_browser.server import Dashboard
from diagnostic_browser.store import EvidenceStore
from diagnostic_browser.browser_host import _safe_host_status


@pytest.mark.asyncio
async def test_full_engine_with_real_chrome_watchdog_and_export(monkeypatch,tmp_path):
    chrome=shutil.which('chromium')
    if not chrome:
        pytest.skip('Chromium not installed for real-browser integration')
    real_store=EvidenceStore
    monkeypatch.setattr(main,'EvidenceStore', lambda path: real_store(path,allow_test_plaintext=True))
    captured=[]
    def dashboard_factory(*args):
        d=Dashboard(*args)
        captured.append(d)
        return d
    monkeypatch.setattr(main,'Dashboard',dashboard_factory)
    with socket.socket() as s:
        s.bind(('127.0.0.1',0))
        port=s.getsockname()[1]
    root=tmp_path/'full-system'
    args=SimpleNamespace(data_dir=str(root),chrome_path=chrome,headless=True,
                         synthetic_lab=True,port=port,url='about:blank')
    engine=asyncio.create_task(main.run(args))
    try:
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            host=_safe_host_status(root)
            if host and host.get('browser_connected') and captured:
                break
            await asyncio.sleep(.2)
        assert host and host['browser_connected']
        assert captured
        d=captured[0]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=d.app),
                                      base_url=f'http://127.0.0.1:{port}') as client:
            assert (await client.get('/api/status')).status_code==401
            assert (await client.post('/api/login',json={'code':d.login_code})).status_code==200
            csrf=(await client.get('/api/session')).json()['csrf']
            headers={'x-csrf-token':csrf}
            status=(await client.get('/api/status')).json()
            assert status['browser']['browser_connected'] is True
            assert status['evidence_encryption']=='TEST_PLAINTEXT'
            result=(await client.post('/api/self-test',headers=headers)).json()
            assert result['collector_delivery'] is True
            assert result['privacy_gate_rejects_unapproved_fields'] is True
            assert result['evidence_encryption_verified'] is False
            assert (await client.post('/api/incidents',headers=headers)).status_code==200
            exported=await client.post('/api/export',headers=headers,json={'preset':'engineering'})
            assert exported.status_code==200, exported.text
            manifest=exported.json()
            assert manifest['event_count']>=2
            content=(await client.get('/api/export/file/'+manifest['filename'])).content
            assert content.startswith(b'PK')
            assert b'SYNTHETIC_SECRET_SHOULD_BE_REJECTED' not in content
    finally:
        (root/'engine.stop').touch()
        await asyncio.wait_for(engine,timeout=25)
        assert not _safe_host_status(root)
        reader=real_store(root,read_only=True,allow_test_plaintext=True)
        try:
            assert reader.count()>=2
            assert reader.integrity()
        finally:
            reader.close()
