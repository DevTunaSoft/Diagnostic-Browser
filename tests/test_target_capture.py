"""Tests for the operator-chosen capture target (Diagnose a URL).

The live browser restart is validated on the Windows runner; here we lock the
pure logic: target validation, child cmd/env construction, persistence, and the
dashboard endpoints (auth/CSRF/validation) with a stubbed browser host.
"""
from __future__ import annotations
import asyncio
from types import SimpleNamespace
import httpx
import pytest

from diagnostic_browser.browser_host import validate_target_url, BrowserHostManager
from diagnostic_browser.store import EvidenceStore
from diagnostic_browser.recorder import Recorder
from diagnostic_browser.server import Dashboard


def test_validate_target_accepts_https_origin():
    assert validate_target_url('https://example.com', False) == 'example.com'
    assert validate_target_url('https://Example.COM/', False) == 'example.com'

@pytest.mark.parametrize('bad', [
    'about:blank', 'http://example.com', 'https://login.example.com',
    'https://accounts.google.com', 'ftp://example.com', 'not-a-url', 'https://',
])
def test_validate_target_rejects(bad):
    with pytest.raises(ValueError):
        validate_target_url(bad, False)


def _mgr(tmp_path):
    store = EvidenceStore(tmp_path, allow_test_plaintext=True)
    rec = Recorder(store)
    args = SimpleNamespace(synthetic_lab=False, chrome_path=None, headless=True)
    return BrowserHostManager(tmp_path, rec, store, args), store

@pytest.mark.asyncio
async def test_child_env_carries_authorized_host(tmp_path):
    mgr, store = _mgr(tmp_path)
    try:
        mgr._save_target('https://example.com', 'example.com')
        cmd, env = mgr._child_cmd_env('https://example.com')
        assert '--url' in cmd and 'https://example.com' in cmd
        assert env['DIAGNOSTIC_BROWSER_ALLOWED_HOSTS'] == 'example.com'
        # the host is only in the environment, never on the command line
        assert 'example.com' == env['DIAGNOSTIC_BROWSER_ALLOWED_HOSTS']
    finally:
        store.close()

@pytest.mark.asyncio
async def test_target_persists_across_managers(tmp_path):
    mgr, store = _mgr(tmp_path)
    try:
        mgr._save_target('https://example.com', 'example.com')
        assert mgr.current_target() == {'url': 'https://example.com', 'host': 'example.com'}
        mgr2 = BrowserHostManager(tmp_path, mgr.recorder, store,
                                  SimpleNamespace(synthetic_lab=False, chrome_path=None, headless=True))
        assert mgr2.current_target() == {'url': 'https://example.com', 'host': 'example.com'}
    finally:
        store.close()


class _FakeBrowser:
    def __init__(self): self._t = None
    def current_target(self): return self._t
    async def retarget(self, url):
        if 'login.' in url: raise ValueError('sign-in domains are excluded')
        host = url.split('//')[1].split('/')[0]
        self._t = {'url': url, 'host': host}; return self._t

def _dash(tmp_path):
    store = EvidenceStore(tmp_path, allow_test_plaintext=True); rec = Recorder(store)
    return Dashboard(store, rec, tmp_path, browser=_FakeBrowser()), store

@pytest.mark.asyncio
async def test_target_endpoints(tmp_path):
    d, store = _dash(tmp_path)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=d.app), base_url='http://127.0.0.1') as c:
            assert (await c.get('/api/target')).status_code == 401
            await c.post('/api/login', json={'code': d.login_code})
            csrf = (await c.get('/api/session')).json()['csrf']
            assert (await c.get('/api/target')).json()['target'] is None
            assert (await c.post('/api/target', json={'url': 'https://example.com'})).status_code == 403  # no CSRF
            h = {'x-csrf-token': csrf}
            ok = await c.post('/api/target', json={'url': 'https://example.com'}, headers=h)
            assert ok.status_code == 200 and ok.json()['target']['host'] == 'example.com'
            assert (await c.get('/api/target')).json()['target']['host'] == 'example.com'
            assert (await c.post('/api/target', json={'url': ''}, headers=h)).status_code == 422
            assert (await c.post('/api/target', json={'url': 'https://login.example.com'}, headers=h)).status_code == 422
    finally:
        store.close()
