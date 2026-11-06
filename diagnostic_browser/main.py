"""Local launcher: Chromium, flight recorder, dashboard and independent watchdog."""
from __future__ import annotations
import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
import uvicorn
from .store import EvidenceStore
from .profile_lock import lock_profile
from .policy import Scope
from .recorder import Recorder
from .browser_host import BrowserHostManager
from .server import Dashboard

async def run(args):
    root=Path(args.data_dir).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True,mode=0o700)
    store=EvidenceStore(root)
    recorder=Recorder(store)
    browser=BrowserHostManager(root,recorder,store,args)
    server=Dashboard(store,recorder,root,browser)
    config=uvicorn.Config(server.app,host='127.0.0.1',port=args.port,log_level='warning',access_log=False)
    uvserver=uvicorn.Server(config)
    heartbeat=root/'collector.heartbeat'
    engine_stop=root/'engine.stop'
    watchdog_stop=root/'watchdog.stop'
    watchdog_stop.unlink(missing_ok=True)
    worker_cmd=([sys.executable,'--watchdog-child'] if getattr(sys,'frozen',False) else [sys.executable,'-m','diagnostic_browser.watchdog'])
    watchdog=subprocess.Popen(worker_cmd + [
       '--heartbeat',str(heartbeat),'--report',str(root/'watchdog.jsonl'),'--stop',str(watchdog_stop),'--parent',str(os.getpid())],
       stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    task=None
    pulse_task=None
    dashboard_restart_count=0
    dashboard_restart_limit=3
    dashboard_unavailable=False
    async def pulse():
        while True:
            current=recorder.health()
            chrome_health=browser.health()
            payload={'time':time.time(),'recorder_state':current['state'],
                     'writer_running':current['writer_running'],
                     'queued':current['queued'],
                     'browser_state':chrome_health['state'],
                     'browser_connected':chrome_health['browser_connected'],
                     'dashboard_state': 'FAILED' if dashboard_unavailable else (
                         'RUNNING' if task and not task.done() else 'STARTING')}
            # Atomic replacement avoids partial watchdog reads.
            pending=heartbeat.with_name('collector.heartbeat.tmp')
            pending.write_text(json.dumps(payload),encoding='utf-8')
            os.replace(pending,heartbeat)
            await asyncio.sleep(2)
    try:
        await recorder.start()
        pulse_task=asyncio.create_task(pulse())
        print(f'LOCAL DASHBOARD: http://127.0.0.1:{args.port}/',flush=True)
        print(f'LOCAL LOGIN CODE: {server.login_code}',flush=True)
        print('Diagnostic recording is restricted to explicitly configured authorized hosts.'+ (' TEST LOOPBACK SCOPE ENABLED.' if args.synthetic_lab else ''),flush=True)
        task=asyncio.create_task(uvserver.serve())
        try:await browser.start(args.url)
        except Exception as err:
            browser.status='FAILED'
            recorder.accept('health','error',{'target':'browser','code':'BROWSER_LAUNCH_FAILED'})
            print(f'Browser launch failed: {type(err).__name__} (details withheld from logs)',flush=True)
        if not args.headless:webbrowser.open(f'http://127.0.0.1:{args.port}/')
        while not uvserver.should_exit:
            if engine_stop.exists():
                uvserver.should_exit=True
                break
            if task.done() and not uvserver.should_exit and not dashboard_unavailable:
                # Consume the exception without writing potentially sensitive raw
                # framework error messages into logs.
                try: task.exception()
                except asyncio.CancelledError: pass
                # The UI is not the CDP owner. A transient UI fault must not
                # close the authenticated browser or interrupt recording.
                # Use bounded restart attempts, preserving truthful health.
                dashboard_restart_count += 1
                recorder.accept('health', 'error', {'target': 'dashboard',
                                'code': 'DASHBOARD_RESTART_REQUIRED'})
                if dashboard_restart_count > dashboard_restart_limit:
                    # No restart storm; Chrome and the recorder remain alive.
                    # The separate repair utility can investigate this state.
                    dashboard_unavailable=True
                else:
                    await asyncio.sleep(min(2 ** dashboard_restart_count, 8))
                    uvserver=uvicorn.Server(uvicorn.Config(server.app,host='127.0.0.1',
                            port=args.port,log_level='warning',access_log=False))
                    task=asyncio.create_task(uvserver.serve())
            await asyncio.sleep(0.5)
    finally:
        uvserver.should_exit=True
        if task:
            try:await asyncio.wait_for(task,5)
            except (asyncio.TimeoutError,asyncio.CancelledError):task.cancel()
        try:
            await browser.stop(deliberate=engine_stop.exists())
        finally:
            try:
                await recorder.stop()
            finally:
                if pulse_task:
                    pulse_task.cancel()
                    try:await pulse_task
                    except asyncio.CancelledError:pass
                watchdog_stop.touch()
                try:watchdog.wait(timeout=5)
                except subprocess.TimeoutExpired:watchdog.terminate()
                store.close()

def main():
    if len(sys.argv)>1 and sys.argv[1]=='--browser-host-child':
        sys.argv.pop(1)
        from .browser_host import main as host_main
        return host_main()
    if len(sys.argv)>1 and sys.argv[1]=='--watchdog-child':
        sys.argv.pop(1)
        from .watchdog import main as watchdog_main
        return watchdog_main()
    if len(sys.argv)>1 and sys.argv[1]=='--ai-child':
        sys.argv.pop(1)
        from .offline_ai import main as ai_main
        return ai_main()
    if len(sys.argv)>1 and sys.argv[1]=='--verify-bundle':
        from .bundle import verify_bundled_runtime
        try:
            print(json.dumps(verify_bundled_runtime(),sort_keys=True),flush=True)
            return 0 if getattr(sys,'frozen',False) else 2
        except (RuntimeError,ImportError,OSError) as exc:
            print(json.dumps({'verified':False,'error':type(exc).__name__}))
            return 2
    if len(sys.argv)>1 and sys.argv[1]=='--repair-child':
        sys.argv.pop(1)
        from .repair import main as repair_main
        return repair_main()
    p=argparse.ArgumentParser(description='Diagnostic Browser V5.0 Windows release candidate')
    default=Path(os.environ.get('LOCALAPPDATA',str(Path.home()/'.local'/'share')))/'DiagnosticBrowser'
    p.add_argument('--data-dir',default=str(default))
    p.add_argument('--chrome-path',default=None,help='Absolute path to installed Chrome/Chromium')
    p.add_argument('--url',default='about:blank')
    p.add_argument('--port',type=int,default=18731)
    p.add_argument('--headless',action='store_true',help='Only for synthetic automated tests')
    p.add_argument('--engine',action='store_true',help=argparse.SUPPRESS)
    p.add_argument('--detached',action='store_true',help='Launch engine independently of this command')
    p.add_argument('--synthetic-lab',action='store_true',help='Explicitly permit loopback synthetic test capture')
    args=p.parse_args()
    # Be robust to callers (e.g. Windows Start-Process) that pass the path with
    # surrounding quotes or stray whitespace; otherwise a leading space makes an
    # absolute path look relative and it is joined onto the current directory.
    if isinstance(args.data_dir, str):
        args.data_dir = args.data_dir.strip().strip('"').strip("'").strip()
    if getattr(sys, 'frozen', False):
        from .bundle import verify_bundled_runtime
        verify_bundled_runtime()
        if args.chrome_path:
            p.error('--chrome-path is not supported for a self-contained executable')
    if not args.engine:
        from .supervisor import supervise, launch_unmonitored
        if args.detached:
            child = launch_unmonitored(args)
            print('Diagnostic Browser engine launched. PID:', child.pid, flush=True)
            print('The diagnostic dashboard requires the engine-generated local login code.', flush=True)
            return 0
        return supervise(args)
    try:
        with lock_profile(Path(args.data_dir)):
            asyncio.run(run(args))
        return 0
    except KeyboardInterrupt:
        return 0

if __name__=='__main__':main()
