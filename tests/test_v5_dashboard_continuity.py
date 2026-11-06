"""UI crash must not be allowed to close a functioning diagnostic browser."""
import asyncio
from types import SimpleNamespace
from diagnostic_browser import main
from diagnostic_browser.store import EvidenceStore
import pytest

@pytest.mark.asyncio
async def test_failed_dashboard_server_recovers_without_closing_browser(monkeypatch,tmp_path):
    events=[]
    original=EvidenceStore
    monkeypatch.setattr(main,'EvidenceStore',lambda path:original(path,allow_test_plaintext=True))
    class Browser:
        status='ARMED'
        def __init__(self,*args):pass
        async def start(self,url):events.append('browser_start')
        async def stop(self, *, deliberate=False):events.append('browser_host_detached' if not deliberate else 'browser_stop')
        def health(self):return {'state':'ARMED','browser_connected':True}
    class Dashboard:
        def __init__(self,*args):self.app=object();self.login_code='SYNTHETIC'
    class Server:
        counter=0
        def __init__(self,cfg):
            self.should_exit=False;Server.counter+=1;self.ordinal=Server.counter
        async def serve(self):
            events.append('dashboard_'+str(self.ordinal))
            if self.ordinal==1:
                raise RuntimeError('synthetic server failure')
            await asyncio.sleep(.1)
            self.should_exit=True
    class Child:
        def __init__(self,*args,**kwargs):pass
        def wait(self,timeout=None):pass
        def terminate(self):pass
    monkeypatch.setattr(main,'BrowserHostManager',Browser)
    monkeypatch.setattr(main,'Dashboard',Dashboard)
    monkeypatch.setattr(main.uvicorn,'Config',lambda *args,**kwargs:object())
    monkeypatch.setattr(main.uvicorn,'Server',Server)
    monkeypatch.setattr(main.subprocess,'Popen',Child)
    args=SimpleNamespace(data_dir=str(tmp_path/'engine'),chrome_path=None,
            headless=True,synthetic_lab=True,port=18731,url='about:blank')
    await asyncio.wait_for(main.run(args),timeout=8)
    assert events==['browser_start','dashboard_1','dashboard_2','browser_host_detached']
    reopen=original(tmp_path/'engine',read_only=True,allow_test_plaintext=True)
    try:
        records=reopen.events()
        assert any(x['fields'].get('code')=='DASHBOARD_RESTART_REQUIRED' for x in records)
    finally:reopen.close()
