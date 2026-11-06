"""Scoped passive CDP event capture from a genuine Chromium browser.

No Fetch interception, request/response body retrieval, cookies or DOM inspection.
CDP may deliver sensitive events in memory; all saved events use finite schemas.
"""
from __future__ import annotations
import asyncio
import json
from collections import OrderedDict
from .request_ledger import RequestLedger
from urllib.parse import urlsplit
from pathlib import Path
from uuid import uuid4
from playwright.async_api import async_playwright, BrowserContext, Page
from .policy import Scope, ERROR_CLASSES, network_code
from .recorder import Recorder
from .environment_policy import classify_navigation_exception

class PageCapture:
    def __init__(self, context: BrowserContext, page: Page, recorder: Recorder, scope: Scope):
        self.context=context;self.page=page;self.recorder=recorder;self.scope=scope
        self.session=None
        self.requests = RequestLedger(scope)
        self.request_evictions_recorded = 0
        self.sockets: OrderedDict[str, bool] = OrderedDict()
        self._seen_responses: OrderedDict[str, bool] = OrderedDict()
        self.capture_successful_requests = True
        self.execution_contexts: dict[int,bool]={}
        self.source = 'page:'+str(id(page))
        self._last_authorized = self.scope.allowed(getattr(page, 'url', ''))
        self._initial_scope_active = False
        self.ready=False
        self.closed=False
        self.unsupported_workers: dict[object,str] = {}
        self.nested_targets: dict[str, tuple[PageCapture, bool]] = {}
        self._nested_parents: dict[str, str | None] = {}
        self._nested_command_id = 0
        self._nested_tasks: set[asyncio.Task] = set()

    def _remember(self, d: OrderedDict, k: str, value, max_size=4096):
        d[k]=value
        if len(d)>max_size:d.popitem(last=False)

    def _guard_event(self, handler, params):
        """Fail visibly, without logging privileged raw CDP event contents."""
        try:
            handler(params)
        except Exception:
            self.ready = False
            try:
                self._set_coverage('FAILING')
            except Exception:
                self.recorder.stats['coverage_write_failure'] += 1
            self.recorder.accept('collection_gap', 'error',
                                 {'reason': 'failed', 'target': 'page'})

    def _subscribe(self, session, event: str, callback) -> None:
        session.on(event, lambda params: self._guard_event(callback, params))

    async def start(self):
        if self.page.is_closed():return
        # Attachment itself must not pause application targets or mutate page state.
        self.session = await self.context.new_cdp_session(self.page)
        s=self.session
        self._subscribe(s,'Network.requestWillBeSent',self.on_request)
        self._subscribe(s,'Network.responseReceived',self.on_response)
        self._subscribe(s,'Network.loadingFailed',self.on_failed)
        self._subscribe(s,'Network.loadingFinished',self.on_finished)
        self._subscribe(s,'Network.webSocketCreated',self.on_socket)
        self._subscribe(s,'Network.webSocketWillSendHandshakeRequest',self.on_socket_handshake)
        self._subscribe(s,'Network.webSocketClosed',self.on_socket_close)
        self._subscribe(s,'Network.webSocketFrameError',self.on_socket_error)
        self._subscribe(s,'Runtime.executionContextCreated',self.on_context_created)
        self._subscribe(s,'Runtime.executionContextDestroyed',self.on_context_destroyed)
        self._subscribe(s,'Runtime.exceptionThrown',self.on_exception)
        self._subscribe(s,'Runtime.consoleAPICalled',self.on_console)
        self._subscribe(s,'Log.entryAdded',self.on_log)
        self._subscribe(s,'Inspector.targetCrashed',self.on_crash)
        await s.send('Network.enable', {'maxTotalBufferSize': 0})
        await s.send('Runtime.enable')
        await s.send('Log.enable')
        await s.send('Inspector.enable')
        # Recursive passive target attachment where supported: OOPIF, workers,
        # service workers. The nested protocol is scoped and content-blind.
        # CDP compatibility errors degrade coverage without breaking Chrome.
        self._subscribe(s, 'Target.attachedToTarget', self.on_nested_attach)
        self._subscribe(s, 'Target.receivedMessageFromTarget', self.on_nested_message)
        self._subscribe(s, 'Target.detachedFromTarget', self.on_nested_detach)
        try:
            await s.send('Target.setAutoAttach', {
                'autoAttach': True, 'waitForDebuggerOnStart': False,
                'flatten': False})
            self.nested_attachment_supported=True
        except Exception:
            self.nested_attachment_supported=False
            self.recorder.store.set_coverage('nested-targets:'+self.source, 'UNSUPPORTED')
        self.ready=True
        self._set_coverage('ACTIVE' if self.scope.allowed(self.page.url) else 'EXCLUDED')
        self.page.on('close',lambda: self.close())
        self.page.on('framenavigated',lambda frame: self._guard_event(self.on_navigation, frame))
        # A worker's existence is observable through Playwright, but this
        # capture module has not attached independent Runtime domains to it.
        # Mark that source UNSUPPORTED rather than falsely implying coverage.
        self.page.on('worker', lambda worker: self._guard_event(self.on_worker, worker))


    def _nested_command(self, sid: str, method: str, params: dict | None = None):
        if len(self._nested_tasks) >= 1024:
            self.recorder.accept('collection_gap','warning',
                                 {'reason':'queue_full','target':'worker'})
            return
        self._nested_command_id += 1
        msg = json.dumps({'id': self._nested_command_id, 'method': method,
                          'params': params or {}}, separators=(',', ':'))
        async def send():
            if self.session is None or self.closed:
                return
            try:
                parent_sid=self._nested_parents.get(sid)
                if parent_sid:
                    # Legacy nested sessions are addressed through the parent
                    # target. Recursively route commands rather than incorrectly
                    # assuming all descendant IDs belong to the root session.
                    self._nested_command(parent_sid, 'Target.sendMessageToTarget',
                                         {'sessionId':sid,'message':msg})
                else:
                    await self.session.send('Target.sendMessageToTarget', {
                        'sessionId': sid, 'message': msg})
            except Exception:
                target = self.nested_targets.get(sid)
                if target:
                    self.recorder.store.set_coverage(target[0].source,'FAILING')
                self.recorder.accept('collection_gap','warning',
                                     {'target':'worker','reason':'not_attached'})
        task=asyncio.create_task(send())
        self._nested_tasks.add(task)
        task.add_done_callback(self._nested_tasks.discard)

    def on_nested_attach(self, p, parent_session_id: str | None = None):
        sid=p.get('sessionId')
        info=p.get('targetInfo') or {}
        kind=info.get('type')
        if not isinstance(sid,str) or not sid or len(sid)>256:
            return
        if kind not in ('iframe','worker','shared_worker','service_worker'):
            return
        if len(self.nested_targets) >= 256:
            self.recorder.accept('collection_gap','warning',
                                 {'reason':'queue_full','target':'worker'})
            return
        # Never persist the raw target URL or target ID: evaluate origin only.
        authorized=self.scope.allowed(info.get('url','')) and self._page_authorized()
        child=PageCapture(self.context,self.page,self.recorder,self.scope)
        child.source=kind+':'+uuid4().hex
        child.ready=True
        self.nested_targets[sid]=(child,authorized)
        self._nested_parents[sid]=parent_session_id
        self.recorder.store.set_coverage(child.source,'ACTIVE' if authorized else 'EXCLUDED')
        # Passive subscriptions only; no script injection or debugger pausing.
        for method in ('Runtime.enable','Network.enable','Log.enable','Inspector.enable'):
            self._nested_command(sid,method)
        self._nested_command(sid,'Target.setAutoAttach', {
            'autoAttach':True,'waitForDebuggerOnStart':False,'flatten':False})

    def on_nested_detach(self,p):
        sid=p.get('sessionId')
        child=self.nested_targets.pop(sid,None)
        self._nested_parents.pop(sid,None)
        if child:
            self.recorder.store.set_coverage(child[0].source,'DISCONNECTED')

    def on_nested_message(self,p):
        sid=p.get('sessionId')
        item=self.nested_targets.get(sid)
        if not item or not item[1] or not self._page_authorized():
            return
        raw=p.get('message')
        if not isinstance(raw,str) or len(raw)>262144:
            self.recorder.accept('collection_gap','warning',
                                 {'target':'worker','reason':'unavailable'})
            return
        try:
            event=json.loads(raw)
        except (ValueError,TypeError):
            return
        if not isinstance(event,dict) or not isinstance(event.get('params'),dict):
            return
        # Do not record responses or arbitrary message contents, even in debug.
        child=item[0]
        handlers={
            'Runtime.executionContextCreated':child.on_context_created,
            'Runtime.executionContextDestroyed':child.on_context_destroyed,
            'Runtime.exceptionThrown':child.on_exception,
            'Runtime.consoleAPICalled':child.on_console,
            'Log.entryAdded':child.on_log,
            'Network.requestWillBeSent':child.on_request,
            'Network.responseReceived':child.on_response,
            'Network.loadingFailed':child.on_failed,
            'Network.loadingFinished':child.on_finished,
            'Network.webSocketCreated':child.on_socket,
            'Network.webSocketWillSendHandshakeRequest':child.on_socket_handshake,
            'Network.webSocketClosed':child.on_socket_close,
            'Network.webSocketFrameError':child.on_socket_error,
            'Inspector.targetCrashed':child.on_crash,
            'Target.attachedToTarget':self.on_nested_attach,
            'Target.detachedFromTarget':self.on_nested_detach,
        }
        method=event.get('method')
        if method=='Target.attachedToTarget':
            self.on_nested_attach(event['params'],parent_session_id=sid)
            return
        if method=='Target.receivedMessageFromTarget':
            self.on_nested_message(event['params'])
            return
        handler=handlers.get(method)
        if handler:
            self._guard_event(handler,event['params'])

    def on_worker(self, worker):
        source = 'worker:' + uuid4().hex
        self.unsupported_workers[worker] = source
        self.recorder.store.set_coverage(source, 'UNATTACHED' if getattr(self,'nested_attachment_supported',False) else 'UNSUPPORTED')
        def worker_closed():
            self.unsupported_workers.pop(worker, None)
            self.recorder.store.set_coverage(source, 'DISCONNECTED')
        worker.on('close', worker_closed)

    def _set_coverage(self,state):
        self.recorder.store.set_coverage(self.source,state)

    def on_navigation(self,frame):
        if frame==self.page.main_frame:
            self._last_authorized = self.scope.allowed(frame.url)
            self._initial_scope_active = False
            self.execution_contexts.clear()
            # Do not discard pending authorized requests on a same-scope
            # navigation: their late responses may contain the original failure.
            # Crossing into an excluded origin MUST clear all request state.
            if not self.scope.allowed(frame.url):
                self.requests.reset()
                self.sockets.clear()
                self._seen_responses.clear()
                for child, _ in self.nested_targets.values():
                    self.recorder.store.set_coverage(child.source,'EXCLUDED')
                self.nested_targets.clear()
                self._nested_parents.clear()
            self._set_coverage('ACTIVE' if self.scope.allowed(frame.url) else 'EXCLUDED')

    def close(self):
        if self.closed:
            return
        self.closed=True
        for task in list(self._nested_tasks):
            task.cancel()
        for child, _ in self.nested_targets.values():
            self.recorder.store.set_coverage(child.source,'DISCONNECTED')
        self.nested_targets.clear()
        self._nested_parents.clear()
        self._set_coverage('DISCONNECTED')

    def _page_authorized(self, initial_request=None):
        # In the initial about:blank document, a permitted navigation may
        # already be dispatching requests before page.url has updated.
        if self.page is None:  # Protocol unit-test harness without a real tab.
            return True
        page_url = getattr(self.page, 'url', '')
        if self.scope.allowed(page_url):
            return True
        if page_url == 'about:blank':
            if initial_request is not None and self.scope.allowed(initial_request):
                self._initial_scope_active = True
                return True
            return self._initial_scope_active
        return False

    def on_request(self, p):
        request = p.get('request') if isinstance(p.get('request'), dict) else {}
        if not self._page_authorized(request.get('url')):
            return
        previous, current = self.requests.begin(p)
        if self.requests.evictions > self.request_evictions_recorded:
            delta = self.requests.evictions - self.request_evictions_recorded
            self.request_evictions_recorded = self.requests.evictions
            try:
                self.recorder.store.record_loss('REQUEST_EVICTED','request_ledger',delta)
            except Exception:
                self.recorder.stats['unpersisted_loss_notices'] += delta
        if previous and previous.authorized:
            response = p.get('redirectResponse') or {}
            # A redirect is an independent hop, even though CDP reuses the requestId.
            # Do not record destinations or user-supplied redirect query strings.
            status = response.get('status')
            if (isinstance(status, (int, float)) and not isinstance(status, bool)
                    and 100 <= int(status) <= 599 and self.scope.allowed(response.get('url', ''))):
                self._http_event(previous, int(status), 'Other', response)
        if not current or not current.authorized:
            return
        if current.route in ('socket.io', 'cpdom'):
            self.recorder.accept('transport_polling', 'info', {
                'route': current.route, 'socket_state': 'polling',
                'request_ref': current.reference, 'redirect_chain': current.chain,
                'sequence': current.hop,
            })

    def _http_event(self, hop, status, resource, response):
        # Exactly one response-observation event per approved request hop, even
        # when redirectResponse and responseReceived both describe that hop.
        if hop.reference in self._seen_responses:
            return
        self._remember(self._seen_responses, hop.reference, True)
        supported = {'Document','XHR','Fetch','Script','Stylesheet','Image',
                     'WebSocket','Other','Preflight','EventSource','Manifest','Font','Ping'}
        fields = {'method': hop.method, 'status': status, 'route': hop.route,
                  'resource': resource if resource in supported else 'Other',
                  'request_ref': hop.reference, 'redirect_chain': hop.chain,
                  'sequence': hop.hop,
                  'cache': 'yes' if response.get('fromDiskCache') else 'no',
                  'service_worker': 'yes' if response.get('fromServiceWorker') else 'no'}
        if status >= 400:
            self.recorder.accept('http_error', 'error' if status >= 500 else 'warning', fields)
        elif self.capture_successful_requests:
            # An observed HTTP response is NOT proof the application workflow
            # succeeded. These safe metadata events provide pre-failure context.
            self.recorder.accept('http_activity', 'info', fields)

    def on_response(self, p):
        if not self._page_authorized():
            return
        hop = self.requests.get(p.get('requestId'))
        if not hop or not hop.authorized:
            return
        response = p.get('response') or {}
        # Never let a cross-origin redirect inherit an authorized request's scope.
        if not self.scope.allowed(response.get('url', '')):
            return
        status = response.get('status')
        if not isinstance(status, (int, float)) or isinstance(status, bool):
            return
        if 100 <= int(status) <= 599:
            self._http_event(hop, int(status), p.get('type', 'Other'), response)

    def on_failed(self, p):
        if not self._page_authorized():
            self.requests.finish(p.get('requestId'))
            return
        hop = self.requests.finish(p.get('requestId'))
        if not hop or not hop.authorized or p.get('canceled'):
            return
        code = network_code(p.get('errorText'))
        if code == 'ERR_BLOCKED_BY_ADMINISTRATOR':
            # An enterprise navigation block is evidence of an environment
            # restriction, not proof of a target system service failure.
            self.recorder.accept('health','warning',{
                'target':'browser','code':'BROWSER_POLICY_BLOCKED'})
        self.recorder.accept('network_failure', 'error', {
            'method': hop.method, 'route': hop.route,
            'request_ref': hop.reference, 'redirect_chain': hop.chain,
            'sequence': hop.hop, 'error_code': code,
        })

    def on_finished(self, p):
        self.requests.finish(p.get('requestId'))

    def on_socket(self,p):
        if not self._page_authorized(p.get('url')):
            return
        rid=p.get('requestId','')
        allowed=self.scope.allowed(p.get('url',''))
        self._remember(self.sockets,rid,allowed)
        if allowed:self.recorder.accept('websocket_open','info',{'socket_state':'created'})

    def on_socket_handshake(self,p):
        if not self._page_authorized(): return
        if self.sockets.get(p.get('requestId')):
            self.recorder.accept('websocket_open','info',{'socket_state':'handshake'})

    def on_socket_close(self,p):
        if not self._page_authorized():
            self.sockets.pop(p.get('requestId'),None)
            return
        if self.sockets.pop(p.get('requestId'),False):
            self.recorder.accept('websocket_closed','warning',{'socket_state':'closed'})

    def on_socket_error(self,p):
        if not self._page_authorized(): return
        if self.sockets.get(p.get('requestId')):
            self.recorder.accept('websocket_error','error',{'socket_state':'frame_error'})

    def on_context_created(self,p):
        ctx=p.get('context') or {}
        cid=ctx.get('id');origin=ctx.get('origin','')
        if isinstance(cid,int) and not isinstance(cid,bool):
            if len(self.execution_contexts) >= 8192 and cid not in self.execution_contexts:
                # An unbounded context cache could exhaust the recorder during
                # hours-long sessions with many worker and iframe lifecycles.
                self.execution_contexts.clear()
                self.recorder.accept('collection_gap', 'warning',
                                     {'reason':'unavailable', 'target':'frame'})
            self.execution_contexts[cid]=self.scope.allowed(origin)

    def on_context_destroyed(self,p):
        self.execution_contexts.pop(p.get('executionContextId'),None)

    def on_exception(self,p):
        # A former authorized execution context must not leak data after
        # the top-level tab has navigated into an excluded SSO provider.
        if self.page is not None and not self.scope.allowed(self.page.url):
            return
        detail=p.get('exceptionDetails') or {}
        cid=detail.get('executionContextId')
        # Script URL fallback is mandatory when execution origin cannot be established.
        if cid in self.execution_contexts:
            if not self.execution_contexts[cid]:return
        elif not self.scope.allowed(detail.get('url','')):return
        ex=detail.get('exception') or {}
        error_class=ex.get('className','UnknownError')
        if error_class not in ERROR_CLASSES:error_class='UnknownError'
        fields={'error_class':error_class}
        if isinstance(detail.get('lineNumber'),int) and 0<=detail['lineNumber']<=10000000:fields['line']=detail['lineNumber']
        if isinstance(detail.get('columnNumber'),int) and 0<=detail['columnNumber']<=10000000:fields['column']=detail['columnNumber']
        self.recorder.accept('js_exception','error',fields)

    def on_console(self,p):
        if self.page is not None and not self.scope.allowed(self.page.url):
            return
        cid=p.get('executionContextId')
        if not self.execution_contexts.get(cid,False):return
        if p.get('type') in ('warning','error','assert'):
            # No console arguments, descriptions, stack text, or object previews.
            self.recorder.accept('console_warning','warning',{'detail_code':'CONSOLE_WARNING'})

    def on_log(self,p):
        if not self._page_authorized(): return
        entry=p.get('entry') or {}
        if not self.scope.allowed(entry.get('url','')):return
        if entry.get('level') in ('warning','error'):
            self.recorder.accept('security_issue','warning',{'detail_code':'BROWSER_LOG_WARNING'})

    def on_crash(self,p):
        # A crash in an unrelated or authentication tab must not be attributed
        # to the authorized recording scope.
        if self.page is not None and not self.scope.allowed(self.page.url):
            return
        self.recorder.accept('browser_crash','critical',{'target':'page','reason':'crash'})

class BrowserFlight:
    def __init__(self,recorder: Recorder, profile: Path,scope: Scope, chrome_path: str|None=None, headless: bool=False):
        self.recorder=recorder;self.profile=profile;self.scope=scope
        self.chrome_path=chrome_path;self.headless=headless
        self.playwright=None;self.context=None;self.pages={}
        self.status='INITIALIZING'
        self.navigation_blocked_by_policy = False
        self.last_navigation_code = None
        self._repair_task: asyncio.Task | None = None
        self._retry_attempts: dict[Page, int] = {}

    async def start(self, initial_url: str = 'about:blank'):
        from .bundle import is_frozen, configure_bundled_browser
        # Refuse external browsers BEFORE creating any driver/Chrome resources.
        if is_frozen() and self.chrome_path:
            raise RuntimeError('External Chrome paths are disabled in the standalone release')
        if is_frozen():
            configure_bundled_browser()
        self.profile.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.playwright=await async_playwright().start()
        # Playwright's automation launch defaults intentionally modify Chrome's
        # normal scheduling, background behavior and some security protections.
        # Restore these behaviors so the recorder does not mask target system
        # background-tab regressions.  Every flag needs a real-browser test.
        normal_browser_defaults = [
            '--disable-background-timer-throttling',
            '--disable-backgrounding-occluded-windows',
            '--disable-renderer-backgrounding',
            '--disable-back-forward-cache',
            '--disable-hang-monitor',
            '--disable-ipc-flooding-protection',
            '--disable-popup-blocking',
            '--disable-client-side-phishing-detection',
            '--disable-component-update',
            '--disable-background-networking',
            '--disable-breakpad',
            '--disable-extensions',
        ]
        opts=dict(headless=self.headless, user_data_dir=str(self.profile),
                  accept_downloads=True, chromium_sandbox=True,
                  ignore_default_args=normal_browser_defaults)
        # Frozen releases use Playwright's embedded Chromium default.
        if not is_frozen():
            if self.chrome_path:
                opts['executable_path'] = self.chrome_path
            else:
                opts['channel'] = 'chrome'
        # IMPORTANT: Playwright uses launch switches. Windows/Okta parity is NOT validated.
        try:
            self.context=await self.playwright.chromium.launch_persistent_context(**opts)
        except BaseException:
            await self.playwright.stop()
            raise
        self.context.on('page',lambda page: asyncio.create_task(self.attach(page)))
        for page in self.context.pages: await self.attach(page)
        if not self.context.pages:
            page=await self.context.new_page()
            await self.attach(page)
        else:page=self.context.pages[0]
        self.status='ARMED' if all(x.ready for x in self.pages.values()) else 'DEGRADED'
        # Reattach to failed CDP targets without restarting an authenticated
        # browser session. Repairs are bounded and independently verified.
        self._repair_task=asyncio.create_task(self._repair_monitor(), name='cdp-target-health-monitor')
        if initial_url!='about:blank':
            try:
                await page.goto(initial_url,wait_until='domcontentloaded',timeout=30000)
                self.navigation_blocked_by_policy = False
                self.last_navigation_code = None
            except Exception as exc:
                self.status='DEGRADED'
                code = classify_navigation_exception(exc)
                self.last_navigation_code = code
                self.navigation_blocked_by_policy = (code == 'BROWSER_POLICY_BLOCKED')
                self.recorder.accept('health','error',{'target':'browser','code':code})
        return page

    async def attach(self, page: Page):
        existing = self.pages.get(page)
        if existing and existing.ready and not existing.closed:
            return
        if page.is_closed():
            return
        if existing is not None:
            # Old session subscriptions must be disconnected before replacing
            # them, otherwise repeated repairs can multiply recorded events.
            if existing.session is not None:
                try:
                    await existing.session.detach()
                except Exception:
                    self.recorder.stats['cdp_detach_failed'] += 1
            existing.close()
        obj = PageCapture(self.context, page, self.recorder, self.scope)
        self.pages[page] = obj
        self.recorder.store.set_coverage(obj.source, 'UNATTACHED')
        def forget_closed_page():
            # A callback from a replaced session must not remove its successor.
            if self.pages.get(page) is obj:
                obj.close()
                self.pages.pop(page, None)
                self._retry_attempts.pop(page, None)
        page.on('close', forget_closed_page)
        try:
            await obj.start()
            self._retry_attempts.pop(page, None)
        except Exception:
            obj.ready = False
            self.recorder.store.set_coverage(obj.source, 'FAILING')
            self.recorder.accept('collection_gap', 'error',
                                 {'reason': 'not_attached', 'target': 'page'})

    async def _repair_monitor(self):
        while self.context is not None:
            await asyncio.sleep(3.0)
            if self.status == 'STOPPED':
                return
            for page, obj in list(self.pages.items()):
                if page.is_closed() or obj.closed or obj.ready:
                    continue
                retries = self._retry_attempts.get(page, 0)
                if retries >= 3:
                    self.status = 'DEGRADED'
                    continue
                self._retry_attempts[page] = retries + 1
                self.recorder.store.set_coverage(obj.source, 'RECOVERING')
                try:
                    await self.attach(page)
                except Exception:
                    # Browser remains usable; no Chrome restart is attempted.
                    self.status = 'DEGRADED'
                if page in self.pages and self.pages[page].ready:
                    self.status = ('ARMED' if all(o.ready or o.closed for o in self.pages.values())
                                   else 'DEGRADED')
                    self.recorder.accept('health','info',
                                         {'target':'collector','code':'RECORDER_HEALTH_OK'})

    async def stop(self):
        self.status='STOPPED'
        if self._repair_task is not None:
            self._repair_task.cancel()
            try:
                await self._repair_task
            except asyncio.CancelledError:
                pass
        if self.context:
            try:await self.context.close()
            except Exception:pass
        if self.playwright:await self.playwright.stop()
        self.status='STOPPED'

    def health(self):
        connected = bool(self.context and self.context.browser
                         and self.context.browser.is_connected())
        state = self.status
        if self.context is not None and not connected and self.status not in ('STOPPED','FAILED'):
            state = 'FAILED'
        elif any(not x.ready and not x.closed for x in self.pages.values()):
            state = 'DEGRADED'
        active = sum(bool(x.ready and not x.closed and self.scope.allowed(x.page.url))
                     for x in self.pages.values())
        return dict(state=state, monitored_pages=active, pages_total=len(self.pages),
                    browser_connected=connected,
                    navigation_blocked_by_policy=self.navigation_blocked_by_policy,
                    last_navigation_code=self.last_navigation_code,
                    known_unmonitored_targets='Nested CDP target attachment requires runtime verification',
                    collector_coverage='PARTIAL' if self.context else 'NONE')
