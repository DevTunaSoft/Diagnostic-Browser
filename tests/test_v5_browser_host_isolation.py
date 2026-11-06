"""Actual IPC and lifecycle tests for the independent browser host."""
from __future__ import annotations
import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest
from diagnostic_browser.browser_host import (
    BrowserHostManager, BrowserHostServer, HostRecorderProxy, _host_sender,
    _safe_host_status, MAX_PENDING,
)
from diagnostic_browser.recorder import Recorder
from diagnostic_browser.store import EvidenceStore


@pytest.mark.asyncio
async def test_ipc_receipts_recover_across_collector_restart(tmp_path):
    """Host retains events on collector loss and reports them once after restart."""
    store = EvidenceStore(tmp_path, allow_test_plaintext=True)
    rec = Recorder(store,auto_incident=False)
    await rec.start()
    listener = BrowserHostServer(tmp_path, rec, store)
    listener.loop = asyncio.get_running_loop()
    listener.start()
    proxy = HostRecorderProxy()
    ended = threading.Event()
    sender = threading.Thread(target=_host_sender,args=(tmp_path,proxy,ended),daemon=True)
    sender.start()
    try:
        assert proxy.accept('js_exception','error',{'error_class':'TypeError'})
        deadline = time.monotonic()+7
        while store.count() != 1 and time.monotonic() < deadline:
            await asyncio.sleep(.05)
        assert store.count() == 1
        assert proxy.size() == 0
        # Collector failure: queue safe events while its socket is absent.
        listener.close()
        await asyncio.sleep(.25)
        assert proxy.accept('network_failure','error',{'error_code':'ERR_CONNECTION_RESET'})
        await asyncio.sleep(.25)
        assert proxy.size() > 0
        # Simulate new controller using the same durable evidence store.
        listener2 = BrowserHostServer(tmp_path, rec, store)
        listener2.loop = asyncio.get_running_loop()
        listener2.start()
        try:
            deadline = time.monotonic()+9
            while store.count() < 2 and time.monotonic()<deadline:
                await asyncio.sleep(.1)
            assert store.count() == 2
            events=store.events()
            assert {e['kind'] for e in events} == {'js_exception','network_failure'}
            assert proxy.size() == 0
        finally:
            listener2.close()
    finally:
        ended.set()
        listener.close()
        await rec.stop()
        store.close()


@pytest.mark.asyncio
async def test_replayed_ipc_event_is_idempotent(tmp_path):
    store = EvidenceStore(tmp_path,allow_test_plaintext=True)
    rec=Recorder(store)
    await rec.start()
    reference=uuid4().hex
    try:
        time_seen=datetime.now(timezone.utc)
        assert await rec.ingest_confirmed('health','info',{'code':'READY'},time_seen,reference)
        assert await rec.ingest_confirmed('health','info',{'code':'READY'},time_seen,reference)
        assert store.count()==1
        assert store.events()[0]['id']==reference
    finally:
        await rec.stop()
        store.close()


def test_host_proxy_rejects_secret_payloads_and_bounds_memory():
    proxy=HostRecorderProxy()
    assert not proxy.accept('health','info',{'password':'supersecret'})
    assert proxy.size()==0
    for _ in range(MAX_PENDING):
        assert proxy.accept('health','info',{'code':'READY'})
    assert not proxy.accept('health','info',{'code':'READY'})
    assert proxy.stats['queue_full']==1
    assert proxy.size()==MAX_PENDING
    assert 'supersecret' not in str(list(proxy.events))


@pytest.mark.asyncio
async def test_real_chromium_host_survives_dashboard_controller_detach(tmp_path):
    """Real browser launch, separate host PID, no requirement for blocked navigation."""
    browser=shutil.which('chromium')
    if not browser:
        pytest.skip('System Chromium is unavailable')
    root=tmp_path/'isolated'
    store=EvidenceStore(root,allow_test_plaintext=True)
    rec=Recorder(store)
    await rec.start()
    args=SimpleNamespace(chrome_path=browser,headless=True,synthetic_lab=True)
    manager=BrowserHostManager(root,rec,store,args)
    # This test must not make requests to blocked external destinations.
    try:
        await manager.start('about:blank')
        initial=_safe_host_status(root)
        assert initial and initial['browser_connected'] is True
        pid=initial['pid']
        await manager.stop(deliberate=False)
        await asyncio.sleep(2.2)
        after=_safe_host_status(root)
        assert after and after['pid']==pid
        assert after['browser_connected'] is True
        assert after['state'] in ('ARMED','DEGRADED')
        # Now restart the actual collector and reconnect to the existing host:
        # the browser host PID MUST remain the same across collector lifetimes.
        await rec.stop()
        store.close()
        store2=EvidenceStore(root,allow_test_plaintext=True)
        rec2=Recorder(store2)
        await rec2.start()
        manager2=BrowserHostManager(root,rec2,store2,args)
        try:
            await manager2.start('about:blank')
            assert manager2.process is None  # connected to existing host
            again=_safe_host_status(root)
            assert again and again['pid']==pid
            assert again['browser_connected'] is True
            await manager2.stop(deliberate=True)
        finally:
            await manager2.stop(deliberate=False)
            await rec2.stop()
            store2.close()
        # Explicit operator stop only, never kill a live authenticated browser.
        (root/'browser-host.stop').touch()
        deadline=time.monotonic()+12
        while time.monotonic()<deadline and _safe_host_status(root):
            await asyncio.sleep(.2)
        assert not _safe_host_status(root)
    finally:
        (root/'browser-host.stop').touch()
        await manager.stop(deliberate=False)
        if rec.status != 'STOPPED':
            await rec.stop()
        store.close()


@pytest.mark.asyncio
async def test_conflicting_replayed_id_rejected_without_mutating_evidence(tmp_path):
    store=EvidenceStore(tmp_path,allow_test_plaintext=True)
    rec=Recorder(store,auto_incident=False)
    await rec.start()
    eid=uuid4().hex
    at=datetime.now(timezone.utc)
    try:
        assert await rec.ingest_confirmed('health','info',{'code':'READY'},at,eid)
        with pytest.raises(OSError, match='could not be committed'):
            await rec.ingest_confirmed('health','info',{'code':'BROWSER_POLICY_BLOCKED'},at,eid)
        assert store.count()==1
        assert store.events()[0]['fields']['code']=='READY'
    finally:
        await rec.stop()
        store.close()


@pytest.mark.asyncio
async def test_host_overflow_loss_notice_reaches_durable_ledger(tmp_path):
    store=EvidenceStore(tmp_path,allow_test_plaintext=True)
    rec=Recorder(store,auto_incident=False)
    await rec.start()
    listener=BrowserHostServer(tmp_path,rec,store)
    listener.loop=asyncio.get_running_loop()
    listener.start()
    proxy=HostRecorderProxy()
    proxy.stats['queue_full']=7
    ended=threading.Event()
    thread=threading.Thread(target=_host_sender,args=(tmp_path,proxy,ended),daemon=True)
    thread.start()
    try:
        deadline=time.monotonic()+7
        while not store.losses() and time.monotonic()<deadline:
            await asyncio.sleep(.05)
        losses=store.losses()
        assert len(losses)==1
        assert losses[0]['count']==7
        assert losses[0]['source']=='browser'
        assert losses[0]['reason']=='QUEUE_FULL'
    finally:
        ended.set()
        listener.close()
        await rec.stop()
        store.close()


def test_custom_domain_and_same_host_sso_paths_are_excluded():
    from diagnostic_browser.policy import Scope
    scope=Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org'))
    allowed=('https://portal.example.org/api/dispatch',
             'https://example.org/socket.io/')
    blocked=('https://login.example.org/login?code=SECRET',
             'https://sso.example.org/auth',
             'https://portal.example.org/oauth2/authorize',
             'https://example.org/connect/authorize?code=SECRET',
             'https://okta.example.org/oauth/callback',
             'https://portal.example.org/saml/metadata')
    assert all(scope.allowed(u) for u in allowed)
    assert not any(scope.allowed(u) for u in blocked)


def test_coverage_identifiers_cannot_contain_urls_or_secrets():
    proxy=HostRecorderProxy()
    proxy.set_coverage('page:12345','ACTIVE')
    proxy.set_coverage('worker:'+'a'*32,'ACTIVE')
    proxy.set_coverage('nested-targets:page:12345','ACTIVE')
    assert proxy.size()==3
    for value in ['https://example.org/patient?id=SECRET',
                  'page:token=PHI1234', 'page:12345?access_token=TOKEN',
                  'page:12345/secret']:
        proxy.set_coverage(value,'ACTIVE')
    assert proxy.size()==3
    assert proxy.stats['privacy_rejected']==4


def test_browser_launcher_commandline_refuses_credential_bearing_url():
    from diagnostic_browser.browser_host import validate_launch_url
    assert validate_launch_url('about:blank',False)=='about:blank'
    assert validate_launch_url('https://example.org/',False)=='https://example.org/'
    with pytest.raises(ValueError):
        validate_launch_url('https://example.org/api/patient/12345',False)
    with pytest.raises(ValueError):
        validate_launch_url('https://example.org/?token=SECRET',False)
    with pytest.raises(ValueError):
        validate_launch_url('https://user:password@example.org/',False)
    with pytest.raises(ValueError):
        validate_launch_url('http://127.0.0.1:8080/',False)
    assert validate_launch_url('http://127.0.0.1:8080/',True)=='http://127.0.0.1:8080/'
