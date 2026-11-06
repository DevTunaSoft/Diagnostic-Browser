"""Isolated browser lifecycle host and authenticated, one-way diagnostic bridge.

A resident browser host owns Playwright/Chrome.  The evidence collector and
Dashboard run in a *different* process and can restart without closing Chrome.
No public CDP endpoint, URL-bearing protocol payload, or raw console object is
transmitted over IPC.  The host retains a bounded *sanitized* memory queue on
collector interruption and discloses dropped observations.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter, deque
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import threading
import time
from multiprocessing.connection import Client, Listener
from multiprocessing import AuthenticationError
from uuid import uuid4
from urllib.parse import urlsplit

from .policy import normalize, UnsafeEvent, Scope, COVERAGE_SOURCE_PATTERN
from .store import load_key

MAX_PENDING = 8192
HEARTBEAT_STALE_SECONDS = 8
# The database receiver waits up to 15 seconds for a durable write. Never
# allow a connected but unresponsive collector to block the host indefinitely.
RECEIPT_TIMEOUT_SECONDS = 18.0


def _await_receipt(conn, expected: str, stop: threading.Event,
                   timeout: float = RECEIPT_TIMEOUT_SECONDS) -> None:
    """Require a *durable* acknowledgment, or reconnect and retry same ID.

    This method never executes browser commands and never logs IPC payloads.
    A poll failure must not remove the pending event from the host queue.
    """
    deadline = time.monotonic() + timeout
    while not stop.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ConnectionError('collector receipt timed out')
        if conn.poll(min(remaining, 0.5)):
            ack = conn.recv_bytes(96).decode('ascii')
            if ack != expected:
                raise ConnectionError('collector receipt mismatch')
            return
    raise ConnectionError('browser host stopping before receipt')



def ipc_address(root: Path) -> tuple[str, str]:
    """The Windows endpoint is a named pipe; POSIX uses a private Unix socket."""
    short = hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:24]
    if os.name == 'nt':
        return (r'\\.\pipe\DiagnosticBrowser-' + short, 'AF_PIPE')
    # Unix-domain socket paths have a roughly 108-byte OS limit, even when
    # the profile path is deeply nested. The authenticated socket is mode 0600.
    import tempfile
    return (str(Path(tempfile.gettempdir()) / ('db-' + str(os.getuid()) + '-' + short + '.sock')), 'AF_UNIX')


def _atomic_json(path: Path, data: dict):
    tmp = path.with_suffix('.tmp')
    with tmp.open('w', encoding='utf-8') as stream:
        json.dump(data, stream, separators=(',', ':'), sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)


def _alive(pid: int) -> bool:
    # A status file by itself is NOT proof of process liveness.
    if not isinstance(pid, int) or pid <= 0:
        return False
    if os.name == 'nt':
        from .watchdog import parent_alive
        return parent_alive(pid) is True
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _safe_host_status(root: Path) -> dict | None:
    try:
        obj = json.loads((root / 'browser-host.health.json').read_text('utf-8'))
        if not isinstance(obj, dict):
            return None
        age = time.time() - float(obj['heartbeat'])
        if not -5 < age < HEARTBEAT_STALE_SECONDS or not _alive(obj['pid']):
            return None
        return obj
    except (OSError, ValueError, TypeError, KeyError):
        return None


def validate_launch_url(url: str, synthetic_lab: bool) -> str:
    """Do not expose credentials, patient IDs, or signed links in OS process args.

    Once Chrome opens, normal browsing is available in its address bar.
    """
    if url == 'about:blank':
        return url
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError('initial URL must be a short origin URL')
    try:
        parsed = urlsplit(url)
        if (parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ('', '/')):
            raise ValueError('initial URL must not include credentials, paths or query parameters')
        if parsed.scheme == 'https' and parsed.hostname:
            return url
        if (synthetic_lab and parsed.scheme == 'http'
                and parsed.hostname == '127.0.0.1'):
            return url
    except (TypeError, ValueError) as exc:
        raise ValueError('unsafe initial navigation') from exc
    raise ValueError('unsafe initial navigation')


class HostRecorderProxy:
    """Accepts only sanitized events; never gives Chrome direct database access."""
    def __init__(self):
        self.events: deque[dict] = deque()
        self.lock = threading.Lock()
        self.stats: Counter = Counter()
        self.store = self
        self.connected = False
        self.reported_losses = 0
        self.pending_loss_ref: str | None = None
        self.pending_loss_count = 0
        # A connected socket without a recent response does not prove an
        # operational diagnostic bridge. Active protocol pings establish that.
        self.last_receipt_mono = 0.0

    def accept(self, kind: str, severity: str, fields: dict) -> bool:
        try:
            kind, severity, fields = normalize(kind, severity, fields)
        except (ValueError, TypeError, UnsafeEvent):
            self.stats['privacy_rejected'] += 1
            return False
        return self._queue({'op': 'event', 'kind': kind, 'severity': severity,
                            'fields': fields, 'observed_at': datetime.now(timezone.utc).isoformat(),
                            'event_ref': uuid4().hex})

    def set_coverage(self, source: str, state: str) -> None:
        if not isinstance(source, str) or not re.fullmatch(
                COVERAGE_SOURCE_PATTERN, source) or not isinstance(state, str):
            self.stats['privacy_rejected'] += 1
            return
        if state not in ('ACTIVE','EXCLUDED','UNSUPPORTED','UNATTACHED','DISCONNECTED','FAILING','RECOVERING'):
            return
        self._queue({'op': 'coverage', 'source': source, 'state': state})

    def _queue(self, event: dict) -> bool:
        with self.lock:
            if len(self.events) >= MAX_PENDING:
                # Preserve critical evidence under a flood of normal successful
                # HTTP activity. Never evict index zero: sender may be awaiting
                # its durable acknowledgment, so deleting it would corrupt
                # exactly-once replay and subsequent receipt ordering.
                critical = (event.get('op') == 'event' and
                            event.get('kind') in {
                                'browser_crash', 'js_exception', 'http_error',
                                'network_failure', 'collection_gap',
                                'websocket_error', 'storage_error', 'manual_marker'
                            })
                if critical:
                    for idx in range(1, len(self.events)):
                        older = self.events[idx]
                        if older.get('op') == 'event' and older.get('kind') == 'http_activity':
                            del self.events[idx]
                            self.stats['queue_full'] += 1
                            self.stats['priority_replaced'] += 1
                            break
                    else:
                        self.stats['queue_full'] += 1
                        return False
                else:
                    self.stats['queue_full'] += 1
                    return False
            self.events.append(event)
            return True

    def next(self):
        with self.lock:
            return self.events[0] if self.events else None

    def acknowledge(self):
        with self.lock:
            if self.events:
                self.events.popleft()

    def size(self) -> int:
        with self.lock:
            return len(self.events)


def _host_sender(root: Path, proxy: HostRecorderProxy, stop: threading.Event):
    address, family = ipc_address(root)
    authkey = load_key(root)
    while not stop.is_set():
        try:
            # Authentication protects the one-way collector bridge; the browser
            # CDP pipe never leaves the host process.
            conn = Client(address, family=family, authkey=authkey)
            proxy.connected = True
            try:
                while not stop.is_set():
                    # Known host overflow must be recorded even when its queue
                    # was too full to accept a normal loss event.
                    missing = proxy.stats['queue_full'] - proxy.reported_losses
                    if missing > 0:
                        if proxy.pending_loss_ref is None:
                            proxy.pending_loss_ref = uuid4().hex
                            proxy.pending_loss_count = missing
                        loss = {'op': 'loss', 'event_ref': proxy.pending_loss_ref,
                                'count': proxy.pending_loss_count}
                        conn.send_bytes(json.dumps(loss,separators=(',',':')).encode('utf-8'))
                        _await_receipt(conn, proxy.pending_loss_ref, stop)
                        proxy.last_receipt_mono = time.monotonic()
                        proxy.reported_losses += proxy.pending_loss_count
                        proxy.pending_loss_ref = None
                        proxy.pending_loss_count = 0
                    msg = proxy.next()
                    if msg is None:
                        if time.monotonic() - proxy.last_receipt_mono >= 2.0:
                            ping = uuid4().hex
                            conn.send_bytes(json.dumps({'op': 'ping', 'event_ref': ping},
                                                       separators=(',', ':')).encode('ascii'))
                            _await_receipt(conn, ping, stop)
                            proxy.last_receipt_mono = time.monotonic()
                        stop.wait(0.08)
                        continue
                    conn.send_bytes(json.dumps(msg,separators=(',',':')).encode('utf-8'))
                    _await_receipt(conn, msg.get('event_ref', 'ok'), stop)
                    proxy.last_receipt_mono = time.monotonic()
                    proxy.acknowledge()
            finally:
                conn.close()
        except (OSError, EOFError, BrokenPipeError, ConnectionError,
                AuthenticationError, ValueError, UnicodeError):
            # Malformed or lost collector connections cannot terminate the
            # browser's independent evidence forwarding thread.
            pass
        finally:
            proxy.connected = False
        stop.wait(1)


class BrowserHostServer:
    """Only writer to recorder; receiver never executes browser commands."""
    def __init__(self, root: Path, recorder, store):
        self.root = root
        self.recorder = recorder
        self.store = store
        self.address, self.family = ipc_address(root)
        self.listener = None
        self.current_connection = None
        self.thread = None
        self.closed = False
        self.received = 0
        self.rejected = 0

    def start(self):
        if self.family == 'AF_UNIX':
            # Restricted data directory keeps socket unavailable to other users.
            Path(self.address).unlink(missing_ok=True)
        self.listener = Listener(self.address, family=self.family, authkey=load_key(self.root))
        if self.family == 'AF_UNIX':
            os.chmod(self.address, 0o600)
        self.thread = threading.Thread(target=self._receive, name='browser-host-local-bridge', daemon=True)
        self.thread.start()

    def _receive(self):
        while not self.closed:
            try:
                conn = self.listener.accept()
                self.current_connection = conn
            except AuthenticationError:
                # An unauthorized local connector must not take down the
                # privileged collector listening socket.
                self.rejected += 1
                continue
            except (OSError, EOFError):
                break
            try:
                while not self.closed:
                    # A connected but idle host must not pin this receiver in
                    # recv_bytes forever during shutdown/restart. Polling does
                    # not consume messages or acknowledge any evidence.
                    if not conn.poll(0.5):
                        continue
                    raw = conn.recv_bytes(2048)
                    msg = json.loads(raw)
                    if not isinstance(msg, dict):
                        self.rejected += 1
                        raise ValueError('malformed IPC record')
                    self._dispatch(msg)
                    conn.send_bytes(msg.get('event_ref', 'ok').encode('ascii'))
            except (EOFError, OSError, ValueError, TypeError, ConnectionError):
                self.rejected += 1
            finally:
                self.current_connection = None
                conn.close()

    def _dispatch(self, msg: dict):
        if msg.get('op') == 'event':
            try:
                kind, severity, fields = normalize(msg.get('kind'), msg.get('severity'), msg.get('fields'))
                if (not isinstance(msg.get('event_ref'), str) or len(msg['event_ref']) != 32
                        or any(c not in '0123456789abcdef' for c in msg['event_ref'])):
                    raise ValueError('invalid event reference')
                at = datetime.fromisoformat(msg['observed_at'])
                if at.tzinfo is None:
                    raise ValueError('missing UTC timezone')
                # Prevent hostile or stale observation timestamps being persisted.
                if not -5 <= (datetime.now(timezone.utc)-at).total_seconds() <= 86400:
                    raise ValueError('event timestamp outside accepted range')
            except (ValueError, TypeError, KeyError, UnsafeEvent) as exc:
                self.rejected += 1
                # A disallowed event must never enter the evidence database.
                # But leaving it at the head of the host queue permanently
                # stalls all following evidence. Commit a counted, content-free
                # loss with the SAME ID first; only then ACK that exclusion.
                ref = msg.get('event_ref')
                if isinstance(ref, str) and re.fullmatch(r'[0-9a-f]{32}', ref):
                    async def record_policy_exclusion():
                        self.store.record_loss('POLICY_EXCLUDED', source='browser',
                                               count=1, loss_id=ref)
                    try:
                        receipt = asyncio.run_coroutine_threadsafe(
                            record_policy_exclusion(), self.loop)
                        receipt.result(timeout=15)
                    except Exception as receipt_error:
                        raise ConnectionError('privacy rejection not accounted for') from receipt_error
                    return
                # No trustworthy stable ID: the host cannot safely discard it.
                raise ValueError('invalid sanitized host event') from exc
            # The receiver runs off the main loop; schedule safe recorder input
            # via the recorder's owning loop (asyncio.Queue is not thread-safe).
            from concurrent.futures import TimeoutError as FutureTimeout
            try:
                future = asyncio.run_coroutine_threadsafe(
                    self.recorder.ingest_confirmed(kind, severity, fields, at,
                                                   msg['event_ref']), self.loop)
                future.result(timeout=15)
            except (OSError, ValueError, KeyError, FutureTimeout):
                self.rejected += 1
                # No acknowledgment means the host will retry the same ID.
                raise ConnectionError('durable evidence receipt unavailable')
            self.received += 1
        elif msg.get('op') == 'loss':
            loss_ref, count = msg.get('event_ref'), msg.get('count')
            if (not isinstance(loss_ref, str) or len(loss_ref) != 32
                    or any(c not in '0123456789abcdef' for c in loss_ref)
                    or not isinstance(count, int) or isinstance(count, bool)
                    or not 1 <= count <= 10_000_000):
                self.rejected += 1
                raise ValueError('invalid loss notice')
            async def record():
                self.store.record_loss('QUEUE_FULL', source='browser', count=count, loss_id=loss_ref)
            from concurrent.futures import TimeoutError as FutureTimeout
            try:
                asyncio.run_coroutine_threadsafe(record(), self.loop).result(timeout=15)
            except (FutureTimeout, OSError, ValueError) as exc:
                raise ConnectionError('loss receipt unavailable') from exc
            self.received += 1
        elif msg.get('op') == 'ping':
            ref = msg.get('event_ref')
            if (set(msg) != {'op', 'event_ref'} or not isinstance(ref, str)
                    or not re.fullmatch(r'[0-9a-f]{32}', ref)):
                self.rejected += 1
                raise ValueError('invalid heartbeat request')
            self.received += 1
        elif msg.get('op') == 'coverage':
            if (msg.get('state') in ('ACTIVE','EXCLUDED','UNSUPPORTED','UNATTACHED','DISCONNECTED','FAILING','RECOVERING')
                    and isinstance(msg.get('source'), str) and re.fullmatch(
                        COVERAGE_SOURCE_PATTERN, msg['source'])):
                async def persist_coverage():
                    self.store.set_coverage(msg['source'], msg['state'])
                try:
                    future = asyncio.run_coroutine_threadsafe(persist_coverage(), self.loop)
                    future.result(timeout=15)
                except Exception as exc:
                    # Coverage is part of the evidence. Do not ACK before a
                    # successful write; reconnect and retry on storage faults.
                    self.rejected += 1
                    raise ConnectionError('coverage was not committed') from exc
                self.received += 1
            else:
                self.rejected += 1
                raise ValueError('invalid coverage receipt')
        else:
            self.rejected += 1
            raise ValueError('unrecognized bridge operation')

    def close(self):
        self.closed = True
        if self.current_connection:
            self.current_connection.close()
        if self.listener:
            self.listener.close()
        if self.family == 'AF_UNIX':
            Path(self.address).unlink(missing_ok=True)


class BrowserHostManager:
    """Manages a host independent of the dashboard/collector process lifetime."""
    def __init__(self, root: Path, recorder, store, args):
        self.root, self.recorder, self.store, self.args = root, recorder, store, args
        self.server = BrowserHostServer(root, recorder, store)
        self.process = None
        self.status = 'INITIALIZING'
        self.server.loop = asyncio.get_running_loop()

    async def start(self, initial_url: str):
        initial_url = validate_launch_url(initial_url, self.args.synthetic_lab)
        self.server.start()
        prior = _safe_host_status(self.root)
        if prior is None:
            cmd = ([sys.executable, '--browser-host-child'] if getattr(sys,'frozen',False)
                   else [sys.executable, '-m', 'diagnostic_browser.browser_host'])
            cmd += ['--data-dir', str(self.root), '--url', initial_url]
            if self.args.chrome_path:
                cmd += ['--chrome-path', self.args.chrome_path]
            if self.args.headless:
                cmd.append('--headless')
            if self.args.synthetic_lab:
                cmd.append('--synthetic-lab')
            # Never inherit controller stdout/stderr pipes. A resident browser
            # host must not keep QA subprocess pipes open after the collector
            # exits; Chrome diagnostics must not print sensitive browser data.
            kw = {'stdin': subprocess.DEVNULL, 'stdout': subprocess.DEVNULL,
                  'stderr': subprocess.DEVNULL, 'close_fds': True}
            if getattr(sys, 'frozen', False):
                # The host intentionally survives its collector. PyInstaller
                # onefile must independently unpack for a long-lived child.
                kw['env'] = {**os.environ, 'PYINSTALLER_RESET_ENVIRONMENT': '1'}
            if os.name == 'nt':
                kw['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                kw['start_new_session'] = True
            self.process = subprocess.Popen(cmd, **kw)
        # Frozen onefile can take longer to unpack Chromium and AI model.
        deadline = time.monotonic() + (180 if getattr(sys, "frozen", False) else 15)
        while time.monotonic() < deadline:
            state = _safe_host_status(self.root)
            if state:
                self.status = state['state']
                return
            if self.process and self.process.poll() is not None:
                self.status='FAILED'
                return
            await asyncio.sleep(0.25)
        self.status='UNVERIFIED'

    def health(self):
        state = _safe_host_status(self.root)
        if state is None:
            return {'state':'UNVERIFIED','browser_connected':False,'monitored_pages':0,
                    'collector_coverage':'UNKNOWN','reason':'HOST_HEARTBEAT_UNAVAILABLE'}
        connected = bool(state.get('browser_connected'))
        # A healthy Chrome with disconnected collector is degraded, not green.
        operating = state.get('state')
        bridge = bool(state.get('bridge_connected'))
        result = 'DEGRADED' if not bridge else operating
        return {'state':result, 'browser_connected':connected,
                'monitored_pages':int(state.get('monitored_pages',0)),
                'collector_coverage':'PARTIAL' if bridge else 'INTERRUPTED',
                'pending':int(state.get('pending',0)), 'dropped':int(state.get('dropped',0)),
                'privacy_rejected':int(state.get('privacy_rejected',0))}

    async def stop(self, *, deliberate: bool = False):
        if deliberate:
            (self.root / 'browser-host.stop').touch(mode=0o600)
            if self.process:
                try:
                    await asyncio.to_thread(self.process.wait, 10)
                except subprocess.TimeoutExpired:
                    # Do not kill an authenticated browser when it may be live.
                    pass
        self.server.close()


async def run_host(args):
    from .capture import BrowserFlight
    from .profile_lock import lock_profile
    root = Path(args.data_dir).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    stop_file = root/'browser-host.stop'
    with lock_profile(root/'browser-host-lock'):
        stop_file.unlink(missing_ok=True)
        recorder = HostRecorderProxy()
        end = threading.Event()
        sender = threading.Thread(target=_host_sender,args=(root,recorder,end),daemon=True,
                                  name='sanitized-evidence-transport')
        sender.start()
        browser = BrowserFlight(recorder, root/'chrome-profile',
                                Scope(test_local=True, allowed_hosts=Scope.configured().allowed_hosts) if args.synthetic_lab else Scope.configured(),args.chrome_path,args.headless)
        try:
            await browser.start(args.url)
            while not stop_file.exists():
                status = browser.health()
                _atomic_json(root/'browser-host.health.json', {
                    'heartbeat':time.time(), 'pid':os.getpid(),
                    'state':status['state'], 'browser_connected':status['browser_connected'],
                    'monitored_pages':status['monitored_pages'],
                    'bridge_connected':bool(recorder.connected and
                        time.monotonic() - recorder.last_receipt_mono < 10),
                    'pending':recorder.size(), 'dropped':recorder.stats['queue_full'],
                'privacy_rejected':recorder.stats['privacy_rejected'],
                })
                await asyncio.sleep(1)
        finally:
            end.set()
            # Host belongs to the browser session, not to the dashboard. Only
            # an explicit operator shutdown path reaches browser.stop().
            await browser.stop()
            _atomic_json(root/'browser-host.health.json', {
                'heartbeat':time.time()-60, 'pid':os.getpid(),
                'state':'STOPPED', 'browser_connected':False,
                'monitored_pages':0,'bridge_connected':False,'pending':recorder.size(),
                'dropped':recorder.stats['queue_full'],
                'privacy_rejected':recorder.stats['privacy_rejected'],
            })


def main():
    parser = argparse.ArgumentParser(description='Internal diagnostic browser host')
    parser.add_argument('--data-dir',required=True)
    parser.add_argument('--chrome-path')
    parser.add_argument('--url',default='about:blank')
    parser.add_argument('--headless',action='store_true')
    parser.add_argument('--synthetic-lab',action='store_true')
    args = parser.parse_args()
    args.url = validate_launch_url(args.url, args.synthetic_lab)
    asyncio.run(run_host(args))

if __name__ == '__main__':
    main()
