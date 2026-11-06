"""Launcher lifecycle contract, tested without an unapproved browser session."""
from __future__ import annotations
import asyncio
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import Mock
import pytest
from diagnostic_browser import main
from diagnostic_browser.store import EvidenceStore


@pytest.mark.asyncio
async def test_main_launcher_starts_and_cleans_all_subsystems(monkeypatch,tmp_path):
    calls=[]
    original_store=EvidenceStore
    monkeypatch.setattr(main,'EvidenceStore',lambda path: original_store(path,allow_test_plaintext=True))
    class Browser:
        def __init__(self, *args):
            calls.append('browser_created')
        async def start(self,url):
            calls.append('browser_started')
            assert url=='about:blank'
        async def stop(self, *, deliberate=False):
            calls.append('browser_host_detached' if not deliberate else 'browser_stopped')
        def health(self):
            return {'state':'ARMED','browser_connected':True}
    class Dashboard:
        def __init__(self,*args):
            self.app=object()
            self.login_code='SYNTHETIC_LOGIN_CODE'
    class Server:
        def __init__(self, cfg):self.should_exit=False
        async def serve(self):
            await asyncio.sleep(.05)
            self.should_exit=True
    class Child:
        def __init__(self,*args,**kwargs):calls.append('watchdog_started')
        def wait(self,timeout=None):calls.append('watchdog_stopped')
        def terminate(self):calls.append('watchdog_terminated')
    monkeypatch.setattr(main,'BrowserHostManager',Browser)
    monkeypatch.setattr(main,'Dashboard',Dashboard)
    monkeypatch.setattr(main.uvicorn,'Config',lambda *a,**kw: object())
    monkeypatch.setattr(main.uvicorn,'Server',Server)
    monkeypatch.setattr(main.subprocess,'Popen',Child)
    args=SimpleNamespace(data_dir=str(tmp_path/'app'),chrome_path=None,headless=True,
                         synthetic_lab=True,port=18731,url='about:blank')
    await asyncio.wait_for(main.run(args),timeout=4)
    assert calls.count('watchdog_started')==1
    assert calls.count('browser_started')==1
    assert calls.count('browser_host_detached')==1
    assert calls.count('watchdog_stopped')==1
    assert (tmp_path/'app'/'watchdog.stop').exists()


@pytest.mark.asyncio
async def test_main_launcher_gracefully_reports_browser_launch_failure(monkeypatch,tmp_path):
    calls=[]
    native_store=EvidenceStore
    monkeypatch.setattr(main,'EvidenceStore',lambda path: native_store(path,allow_test_plaintext=True))
    class Browser:
        status='INITIALIZING'
        def __init__(self,*args):pass
        async def start(self,url):raise RuntimeError('synthetic launch failure, no secrets')
        async def stop(self, *, deliberate=False):calls.append('host_detached' if not deliberate else 'closed')
        def health(self):return {'state':self.status,'browser_connected':False}
    class Dashboard:
        def __init__(self,*args):self.app=object();self.login_code='SYNTHETIC'
    class Server:
        def __init__(self, config):self.should_exit=False
        async def serve(self):await asyncio.sleep(.06);self.should_exit=True
    class Child:
        def __init__(self,*args,**kw):pass
        def wait(self,timeout=None):pass
        def terminate(self):pass
    monkeypatch.setattr(main,'BrowserHostManager',Browser)
    monkeypatch.setattr(main,'Dashboard',Dashboard)
    monkeypatch.setattr(main.uvicorn,'Config',lambda *a,**kw: object())
    monkeypatch.setattr(main.uvicorn,'Server',Server)
    monkeypatch.setattr(main.subprocess,'Popen',Child)
    args=SimpleNamespace(data_dir=str(tmp_path/'app'),chrome_path=None,headless=True,
                         synthetic_lab=True,port=18731,url='about:blank')
    await asyncio.wait_for(main.run(args),timeout=4)
    assert calls==['host_detached']
    root=tmp_path/'app'
    reopened=native_store(root,allow_test_plaintext=True,read_only=True)
    try:
        assert any(e['kind']=='health' and e['fields']['code']=='BROWSER_LAUNCH_FAILED'
                   for e in reopened.events())
    finally:
        reopened.close()
