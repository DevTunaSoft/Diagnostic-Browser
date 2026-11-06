#!/usr/bin/env python3
"""Local-only Windows Chrome acceptance: browser + SQLCipher + synthetic failures.

No production site, credentials, network uploads, sandbox workarounds or policy bypass.
Requires a real interactive Windows IT session and managed Chrome that permits CDP.
"""
from __future__ import annotations
import argparse, asyncio, json, os, socket, tempfile, zipfile
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timezone
import uvicorn
from diagnostic_browser.lab import lab
from diagnostic_browser.policy import Scope
from diagnostic_browser.store import EvidenceStore
from diagnostic_browser.recorder import Recorder
from diagnostic_browser.capture import BrowserFlight
from diagnostic_browser.reports import export_bundle

class ManagedPolicyBlocked(RuntimeError):
    """Browser reported an administrator-enforced navigation restriction."""


CANARIES = ('FAKE_PASSWORD_SEED_91','FAKE_PATIENT_SEED_52','FAKE_BEARER_TOKEN_SEED_43')

async def verify(chrome_path: str | None, output: Path):
    if os.name != 'nt':
        raise RuntimeError('interactive Windows acceptance must run on Windows')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        port=sock.getsockname()[1]
    service=uvicorn.Server(uvicorn.Config(lab, host='127.0.0.1',port=port,
                                         log_level='error',access_log=False))
    task=asyncio.create_task(service.serve())
    try:
        for _ in range(100):
            if service.started: break
            if task.done(): raise RuntimeError('synthetic test server failed')
            await asyncio.sleep(.05)
        if not service.started: raise RuntimeError('synthetic server not ready')
        with tempfile.TemporaryDirectory(prefix='diagnostic-windows-lab-') as td:
            root=Path(td)
            store=EvidenceStore(root/'evidence')
            rec=Recorder(store)
            flight=BrowserFlight(rec,root/'profile',Scope(test_local=True),
                                 chrome_path,headless=False)
            await rec.start()
            try:
                page=await asyncio.wait_for(flight.start(f'http://127.0.0.1:{port}/'),timeout=60)
                if flight.navigation_blocked_by_policy:
                    raise ManagedPolicyBlocked('Chrome policy prohibits synthetic test navigation')
                await page.locator('#trigger').click()
                await page.evaluate("""async () => {
                    await fetch('/api/fail').catch(()=>{});
                    await fetch('/api/forbidden').catch(()=>{});
                    await new Promise(resolve => {
                      const sock = new WebSocket(`ws://${location.host}/socket.io/live`);
                      sock.onclose = () => resolve();
                      sock.onerror = () => resolve();
                      setTimeout(resolve, 4000);
                    });
                }""")
                await asyncio.sleep(1.0)
                await rec.flush(strict=True)
                observed=store.events()
                kinds={x['kind'] for x in observed}
                required={'http_error','js_exception','websocket_open','websocket_closed'}
                # The test must fail, not silently skip, when browser diagnostics are missing.
                if not required.issubset(kinds):
                    raise AssertionError('synthetic CDP evidence missing: '+repr(sorted(required-kinds)))
                if flight.health()['browser_connected'] is not True:
                    raise AssertionError('browser CDP disconnected during synthetic workflow')
                exported=export_bundle(store,root/'synthetic-engineering.zip')
                with zipfile.ZipFile(exported['path']) as z:
                    if z.testzip() is not None:raise AssertionError('ZIP checksum error')
                    for name in z.namelist():
                        content=z.read(name)
                        for canary in CANARIES:
                            if canary.encode() in content:
                                raise AssertionError('sensitive synthetic canary escaped into '+name)
                for record in observed:
                    for canary in CANARIES:
                        if canary in str(record):
                            raise AssertionError('sensitive synthetic canary persisted')
                return {'result':'PASS','chrome_cdp':'PASS','synthetic_errors':'PASS',
                        'stored_event_count':len(observed), 'event_categories':sorted(kinds),
                        'encryption_backend':store.encryption_backend,
                        'export_integrity':'PASS','canary_exclusion':'PASS',
                        'real_target system_okta':'NOT_TESTED',
                        'tested_utc':datetime.now(timezone.utc).isoformat()}
            finally:
                await flight.stop()
                await rec.stop()
                store.close()
    finally:
        service.should_exit=True
        await asyncio.wait_for(task,15)


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--chrome-path',default=None)
    p.add_argument('--output',default='validation/windows_real_browser_lab_result.json')
    args=p.parse_args()
    output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True)
    try: result=asyncio.run(verify(args.chrome_path,output))
    except ManagedPolicyBlocked:
        result={'result':'BLOCKED', 'reason':'MANAGED_CHROME_NAVIGATION_POLICY',
                'administrator_override_attempted':False,
                'real_target system_okta':'NOT_TESTED',
                'tested_utc':datetime.now(timezone.utc).isoformat()}
    except Exception as exc:
        result={'result':'FAIL','error_type':type(exc).__name__,
                'details':'Sensitive raw error text intentionally omitted',
                'tested_utc':datetime.now(timezone.utc).isoformat()}
    output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))
    return 0 if result['result']=='PASS' else (2 if result['result']=='BLOCKED' else 1)

if __name__=='__main__':raise SystemExit(main())
