"""Local dashboard API with explicit login, CSRF and same-origin protections."""
from __future__ import annotations
from collections import deque
import asyncio
import html
import secrets
import sys
import time
import re
from uuid import uuid4
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException, Response, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.staticfiles import StaticFiles
from .store import EvidenceStore
from .recorder import Recorder
from .reports import export_bundle

class Dashboard:
    def __init__(self, store:EvidenceStore,recorder:Recorder, root:Path, browser=None):
        self.store=store;self.recorder=recorder;self.root=root;self.browser=browser
        self.login_code=secrets.token_urlsafe(18)
        self.sessions:dict[str,str]={}
        self.session_touched:dict[str,float]={}
        self.failed_logins:deque[float]=deque(maxlen=64)
        self._export_lock=asyncio.Lock()
        self._ai_lock=asyncio.Lock()
        self._integrity_cache=None
        self._integrity_last_check=0.0
        self.app=FastAPI(title='Diagnostic Browser',docs_url=None,redoc_url=None,openapi_url=None)
        self.app.mount('/static',StaticFiles(directory=str(Path(__file__).parent/'static')),name='static')
        self._register()

    def _cached_integrity(self):
        # Running a full SQLCipher page-HMAC and SQLite integrity sweep on each
        # four-second dashboard refresh can starve the recording pipeline.
        # Cache for a bounded time; errors are never cached as healthy.
        now=time.monotonic()
        if self._integrity_cache is None or now-self._integrity_last_check>=60:
            try:
                self._integrity_cache=bool(self.store.integrity())
            except Exception:
                self._integrity_cache=False
            self._integrity_last_check=now
        return self._integrity_cache

    def _watchdog_status(self) -> dict:
        """Require independently refreshed watchdog health, never a stale green light."""
        import json
        from datetime import datetime, timezone
        path=self.root/'watchdog.health.json'
        if not path.is_file():
            return {'state':'UNVERIFIED','reason':'NO_WATCHDOG_HEARTBEAT'}
        try:
            data=json.loads(path.read_text(encoding='utf-8'))
            age=(datetime.now(timezone.utc)-datetime.fromisoformat(data['at'])).total_seconds()
            if age < -5 or age > 10:
                return {'state':'STALE','age_seconds':round(age,1)}
            if not isinstance(data['collector_heartbeat_stale'], bool):
                raise ValueError('invalid collector stale flag')
            recorder_unknown = not isinstance(data.get('recorder_degraded'), bool)
            browser_unknown = not isinstance(data.get('browser_degraded'), bool)
            dashboard_unknown = not isinstance(data.get('dashboard_degraded'), bool)
            # A verified failure is a failure even when another component has
            # unknown health. Only claim OBSERVING when *all* are verified.
            if (data['collector_heartbeat_stale'] or
                data.get('recorder_degraded') is True or
                data.get('browser_degraded') is True or
                data.get('dashboard_degraded') is True):
                state = 'DEGRADED'
            elif recorder_unknown or browser_unknown or dashboard_unknown:
                state = 'UNVERIFIED'
            else:
                state = 'OBSERVING'
            return {'state': state,
                    'age_seconds':round(max(0,age),1),
                    'collector_heartbeat_stale':data['collector_heartbeat_stale'],
                    'recorder_degraded':data.get('recorder_degraded'),
                    'browser_degraded':data.get('browser_degraded'),
                    'dashboard_degraded':data.get('dashboard_degraded')}
        except (OSError, ValueError, KeyError, TypeError):
            return {'state':'UNVERIFIED','reason':'WATCHDOG_HEARTBEAT_UNREADABLE'}

    def _register(self):
        app=self.app
        @app.middleware('http')
        async def local_only(request:Request,call_next):
            if request.url.hostname not in ('127.0.0.1','localhost'):
                return JSONResponse({'error':'invalid host'},status_code=403)
            if request.headers.get('origin') and request.headers['origin'].rstrip('/') != f'{request.url.scheme}://{request.url.netloc}':
                return JSONResponse({'error':'cross-origin request rejected'},status_code=403)
            # A local access code must not be susceptible to unlimited attempts
            # or unbounded JSON request buffering from a local untrusted client.
            if request.method in ('POST', 'PUT', 'PATCH'):
                declared = request.headers.get('content-length')
                if declared is not None and (not declared.isdecimal() or int(declared) > 65536):
                    return JSONResponse({'error':'request too large'},status_code=413)
                # Streaming cap: request.body() alone buffers an arbitrarily
                # large chunked POST before its length can be checked.
                bounded = bytearray()
                async for chunk in request.stream():
                    if len(chunk) > 65536 - len(bounded):
                        return JSONResponse({'error':'request too large'},status_code=413)
                    bounded.extend(chunk)
                request._body = bytes(bounded)
            response=await call_next(request)
            response.headers['Cache-Control']='no-store'
            response.headers['X-Content-Type-Options']='nosniff'
            response.headers['X-Frame-Options']='DENY'
            response.headers['Referrer-Policy']='no-referrer'
            response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
            return response
        def require(request:Request, mutate=False):
            sid=request.cookies.get('diagnostic_session')
            if not sid or sid not in self.sessions:raise HTTPException(401,'login required')
            now=time.monotonic()
            if now-self.session_touched.get(sid,0) > 8*3600:
                self.sessions.pop(sid,None);self.session_touched.pop(sid,None)
                raise HTTPException(401,'session expired')
            csrf=self.sessions[sid]
            if mutate and not secrets.compare_digest(request.headers.get('x-csrf-token',''),csrf):
                raise HTTPException(403,'CSRF failed')
            self.session_touched[sid]=now
            return True
        @app.get('/',response_class=HTMLResponse)
        async def home(request:Request):
            if not request.cookies.get('diagnostic_session') in self.sessions:
                return HTMLResponse((Path(__file__).parent/'static'/'login.html').read_text())
            return HTMLResponse((Path(__file__).parent/'static'/'index.html').read_text())
        @app.post('/api/login')
        async def login(request:Request):
            now=time.monotonic()
            while self.failed_logins and now-self.failed_logins[0] > 60:
                self.failed_logins.popleft()
            if len(self.failed_logins)>=5:
                raise HTTPException(429,'local login rate limited')
            try:
                data=await request.json()
            except (ValueError,TypeError):
                data=None
            if not isinstance(data,dict) or not secrets.compare_digest(str(data.get('code','')),self.login_code):
                self.failed_logins.append(now)
                raise HTTPException(401,'invalid local access code')
            self.failed_logins.clear()
            # Bound session credentials kept in memory; evict oldest idle token.
            if len(self.sessions)>=16:
                oldest=min(self.sessions,key=lambda key:self.session_touched.get(key,0))
                self.sessions.pop(oldest,None);self.session_touched.pop(oldest,None)
            sid=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
            self.sessions[sid]=csrf
            self.session_touched[sid]=now
            result=JSONResponse({'ok':True})
            result.set_cookie('diagnostic_session',sid,httponly=True,samesite='strict',secure=False,path='/')
            return result
        @app.get('/api/session')
        async def session(request:Request):
            require(request)
            return {'csrf':self.sessions[request.cookies['diagnostic_session']]}
        @app.get('/api/status')
        async def status(request:Request):
            require(request)
            return dict(recording=self.recorder.health(),browser=self.browser.health() if self.browser else {'state':'NOT_STARTED'},
                 incidents=len(self.store.incidents()),events=self.store.count(),coverage=self.store.coverage(),
                 known_losses=sum(x['count'] for x in self.store.losses()),
                 watchdog=self._watchdog_status(),
                 integrity=self._cached_integrity(),
                 evidence_encryption=self.store.encryption_backend)
        @app.get('/api/events')
        async def events(request:Request, limit:int=200):
            require(request)
            if not 1<=limit<=1000:raise HTTPException(422,'invalid limit')
            return self.store.recent_events(limit)
        @app.post('/api/ai-summary')
        async def offline_ai_summary(request: Request):
            require(request, True)
            # Only strongly allowlisted event fields, never free-form input.
            from .offline_ai import sanitized_snapshot
            from .bundle import model_path
            if not model_path().is_file():
                raise HTTPException(503, 'local model unavailable')
            if self._ai_lock.locked():
                raise HTTPException(429, 'local inference is already running')
            await self.recorder.flush()
            events = sanitized_snapshot(self.store.recent_events(40))
            import json
            message = json.dumps({'events': events}, separators=(',', ':')).encode('utf-8')
            cmd = ([sys.executable, '--ai-child'] if getattr(sys, 'frozen', False)
                   else [sys.executable, '-m', 'diagnostic_browser.offline_ai'])
            async with self._ai_lock:
                try:
                    child = await asyncio.create_subprocess_exec(*cmd,
                        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL)
                    try:
                        out, _ = await asyncio.wait_for(child.communicate(message), timeout=90)
                    except asyncio.TimeoutError:
                        child.kill()
                        await child.wait()
                        raise HTTPException(503, 'local model timed out')
                    if child.returncode != 0 or len(out) > 4096:
                        raise HTTPException(503, 'local inference unavailable')
                    data = json.loads(out)
                    if data.get('status') != 'LOCAL_UNVERIFIED' or not isinstance(data.get('analysis'), str):
                        raise HTTPException(503, 'local inference unavailable')
                    return {'analysis':data['analysis'][:2048], 'verification':'HYPOTHESIS_ONLY',
                            'cloud_used':False, 'approved_event_count':len(events)}
                except (OSError, ValueError):
                    raise HTTPException(503, 'local inference unavailable')
        @app.get('/api/regression')
        async def regression(request:Request):
            require(request)
            return self.store.compare_baseline()
        @app.post('/api/baseline')
        async def baseline(request:Request):
            require(request,True)
            await self.recorder.flush()
            return self.store.save_baseline()
        @app.get('/api/known-issues')
        async def issues(request:Request):
            require(request)
            return self.store.known_issues()
        @app.post('/api/known-issues')
        async def issue(request:Request):
            require(request,True)
            data=await request.json()
            if not isinstance(data,dict):raise HTTPException(422,'invalid issue')
            try:self.store.upsert_issue(data.get('fingerprint'),data.get('ticket'),data.get('state'))
            except ValueError:raise HTTPException(422,'invalid issue')
            return {'saved':True}
        @app.get('/api/incidents')
        async def incidents(request:Request):
            require(request);return self.store.incidents()
        @app.post('/api/incidents')
        async def mark(request:Request):
            require(request,True)
            # Drain already accepted pre-incident evidence before inserting a
            # manually marked incident into the durable event sequence.
            # Even after a previous known evidence loss, IT must still be able
            # to preserve a new incident. The loss ledger remains part of export.
            from datetime import datetime, timezone
            observed_at = datetime.now(timezone.utc)
            await self.recorder.flush()
            return self.store.mark(observed_at=observed_at)
        @app.post('/api/self-test')
        async def self_test(request:Request):
            require(request,True)
            test_ref=uuid4().hex
            delivered=self.recorder.accept('self_test','info',
                 {'reason':'synthetic','code':'SYNTHETIC_EVENT_ACCEPTED',
                  'request_ref':test_ref})
            # Only a fake field-name canary is used; no real credentials are handled.
            blocked=not self.recorder.accept('health','info',
                 {'password':'SYNTHETIC_SECRET_SHOULD_BE_REJECTED'})
            await self.recorder.flush()
            # Confirm the exact newly generated probe, even if thousands of
            # concurrent events arrive after it; never rely on last-N history.
            observed=self.store.verify_self_test(test_ref)
            result=dict(collector_delivery=bool(delivered and observed),
                 database_commit_readback=bool(observed),
                 privacy_gate_rejects_unapproved_fields=blocked,
                 database_integrity=self._cached_integrity(),
                 evidence_encryption=self.store.encryption_backend,
                 evidence_encryption_verified=(self.store.encryption_backend == 'SQLCIPHER'),
                 known_evidence_losses=sum(x['count'] for x in self.store.losses()),
                 recorder=self.recorder.health(),watchdog=self._watchdog_status(),
                 browser=self.browser.health() if self.browser else {'state':'NOT_STARTED'},
                 unsupported_checks=['Windows WER','DPAPI availability on this OS','AI isolation',
                                     'Real target system/Okta flow'])
            return result
        @app.post('/api/export')
        async def export(request:Request):
            require(request,True)
            data=await request.json()
            preset=data.get('preset','engineering') if isinstance(data,dict) else 'engineering'
            if preset not in ('engineering','internal','system-health'):raise HTTPException(422,'invalid preset')
            await self.recorder.flush()
            # Immutable export identity prevents a newly generated report from
            # replacing a previously verified vendor evidence package.
            name='Diagnostic_Browser_'+preset.replace('-','_')+'_'+uuid4().hex+'.zip'
            # Collect only sanitized process-health metadata in the export.
            health={'recorder':self.recorder.health(),
                    'browser':self.browser.health() if self.browser else {'state':'NOT_STARTED'},
                    'watchdog':self._watchdog_status()}
            def create_snapshot_export():
                reader=EvidenceStore(self.root, read_only=True,
                                         allow_test_plaintext=(self.store.encryption_backend == 'TEST_PLAINTEXT'))
                try:
                    # WAL snapshot is fixed for the complete archive while the
                    # primary writer remains available for browser capture.
                    reader.db.execute('BEGIN')
                    reader.db.execute('SELECT COALESCE(MAX(seq), 0) FROM events').fetchone()
                    return export_bundle(reader,self.root/'exports'/name,preset,health=health)
                finally:
                    if reader.db.in_transaction:
                        reader.db.execute('ROLLBACK')
                    reader.close()
            try:
                async with self._export_lock:
                    result=await asyncio.to_thread(create_snapshot_export)
            except Exception:
                raise HTTPException(500,'export failed; see local diagnostics')
            return dict(filename=name,event_count=result['event_count'],sha256=result['sha256'])
        @app.get('/api/export/file/{filename}')
        async def download(request:Request,filename:str):
            require(request)
            if not re.fullmatch(
                r'Diagnostic_Browser_(?:engineering|internal|system_health)_[a-f0-9]{32}\.zip',
                filename):
                raise HTTPException(404,'invalid export reference')
            from fastapi.responses import FileResponse
            p=self.root/'exports'/filename
            if not p.is_file():raise HTTPException(404,'export not found')
            return FileResponse(p,filename=filename,media_type='application/zip')
