"""Offline tests for the in-app Chromium updater and its API endpoints.

No network and no real browser download occur: the installer and the
"available revision" resolver are injected fakes, so these assert the
guardrails (no downgrade, no sub-floor, incident/writable refusals, auth+CSRF)
deterministically.
"""
from __future__ import annotations
import httpx
import pytest

from diagnostic_browser.chromium_update import (
    ChromiumUpdater, ChromiumUpdateError, SECURITY_FLOOR_REVISION,
    STATUS_UP_TO_DATE, STATUS_UPDATE_AVAILABLE, STATUS_UNKNOWN, STATUS_UNMANAGED,
    default_resolver,
)


def _make_dir_with_rev(tmp_path, rev):
    (tmp_path / f'chromium-{rev}').mkdir(parents=True, exist_ok=True)
    return tmp_path


def test_detects_update_available(tmp_path):
    _make_dir_with_rev(tmp_path, 1200)
    up = ChromiumUpdater(tmp_path, resolve_available=lambda: 1243,
                         installer=lambda rev, d: rev)
    s = up.check()
    assert s.current_revision == 1200 and s.available_revision == 1243
    assert s.status == STATUS_UPDATE_AVAILABLE and s.as_dict()['update_available'] is True


def test_reports_up_to_date(tmp_path):
    _make_dir_with_rev(tmp_path, 1243)
    up = ChromiumUpdater(tmp_path, resolve_available=lambda: 1243, installer=lambda rev, d: rev)
    assert up.check().status == STATUS_UP_TO_DATE


def test_unknown_when_no_resolver(tmp_path):
    _make_dir_with_rev(tmp_path, 1200)
    up = ChromiumUpdater(tmp_path, installer=lambda rev, d: rev)  # no resolver
    assert up.check().status == STATUS_UNKNOWN


def test_unmanaged_without_installer(tmp_path):
    _make_dir_with_rev(tmp_path, 1200)
    up = ChromiumUpdater(tmp_path, resolve_available=lambda: 1243)  # no installer
    assert up.check().status == STATUS_UNMANAGED


def test_apply_installs_newer_revision(tmp_path):
    _make_dir_with_rev(tmp_path, 1200)
    calls = []
    def installer(rev, dest):
        calls.append((rev, dest))
        _make_dir_with_rev(dest, rev)
        return rev
    up = ChromiumUpdater(tmp_path, resolve_available=lambda: 1243, installer=installer)
    result = up.apply()
    assert calls == [(1243, tmp_path)]
    assert result.status == STATUS_UP_TO_DATE and result.current_revision == 1243


def test_apply_refuses_downgrade(tmp_path):
    _make_dir_with_rev(tmp_path, 1300)
    up = ChromiumUpdater(tmp_path, resolve_available=lambda: 1200, installer=lambda rev, d: rev)
    # Resolver claims older than installed -> check() is UP_TO_DATE, apply is a no-op.
    assert up.apply().status == STATUS_UP_TO_DATE


def test_apply_rejects_installer_returning_old_build(tmp_path):
    _make_dir_with_rev(tmp_path, 1200)
    # Installer misbehaves and returns a sub-floor revision; must be rejected.
    up = ChromiumUpdater(tmp_path, resolve_available=lambda: 1243,
                         installer=lambda rev, d: SECURITY_FLOOR_REVISION - 1)
    with pytest.raises(ChromiumUpdateError):
        up.apply()


def test_apply_refused_during_incident(tmp_path):
    _make_dir_with_rev(tmp_path, 1200)
    up = ChromiumUpdater(tmp_path, resolve_available=lambda: 1243,
                         installer=lambda rev, d: rev, incident_active=lambda: True)
    with pytest.raises(ChromiumUpdateError):
        up.apply()
    # force overrides the incident guard
    assert up.apply(force=True).status == STATUS_UP_TO_DATE


def test_frozen_without_writable_is_unmanaged(tmp_path):
    ro = tmp_path / 'ro'
    _make_dir_with_rev(ro, 1200)
    up = ChromiumUpdater(ro, resolve_available=lambda: 1243, installer=lambda rev, d: rev, frozen=True)
    up._writable = lambda: False  # simulate read-only bundled location
    assert up.check().status == STATUS_UNMANAGED


def test_default_resolver_reads_pinned_metadata():
    rev = default_resolver()
    assert rev is None or (isinstance(rev, int) and rev >= SECURITY_FLOOR_REVISION)


def test_evidence_emitted_on_update(tmp_path):
    _make_dir_with_rev(tmp_path, 1200)
    events = []
    up = ChromiumUpdater(tmp_path, resolve_available=lambda: 1243,
                         installer=lambda rev, d: rev,
                         on_evidence=lambda k, s, f: events.append((k, s, f)))
    up.apply()
    kinds = [e[0] for e in events]
    assert kinds.count('browser_update') >= 2  # start + complete
    # Evidence carries only integer revisions, never URLs/paths.
    for _, _, fields in events:
        blob = str(fields)
        assert 'http' not in blob and '/' not in blob


# -- endpoint tests ---------------------------------------------------------
def _dashboard(tmp_path):
    from diagnostic_browser.server import Dashboard
    from diagnostic_browser.store import EvidenceStore
    from diagnostic_browser.recorder import Recorder
    store = EvidenceStore(tmp_path / 'db', allow_test_plaintext=True)
    rec = Recorder(store)
    _make_dir_with_rev(tmp_path, 1200)
    updater = ChromiumUpdater(tmp_path, resolve_available=lambda: 1243,
                              installer=lambda rev, d: (_make_dir_with_rev(d, rev), rev)[1])
    d = Dashboard(store, rec, tmp_path, chromium_updater=updater)
    return d, store


@pytest.mark.asyncio
async def test_status_endpoint_requires_auth(tmp_path):
    d, store = _dashboard(tmp_path)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=d.app),
                                     base_url='http://127.0.0.1') as c:
            assert (await c.get('/api/chromium/status')).status_code == 401
    finally:
        store.close()


@pytest.mark.asyncio
async def test_update_requires_csrf_and_then_succeeds(tmp_path):
    d, store = _dashboard(tmp_path)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=d.app),
                                     base_url='http://127.0.0.1') as c:
            await c.post('/api/login', json={'code': d.login_code})
            csrf = (await c.get('/api/session')).json()['csrf']
            # status visible after auth
            body = (await c.get('/api/chromium/status')).json()
            assert body['update_available'] is True and body['available_revision'] == 1243
            # mutation without CSRF rejected
            assert (await c.post('/api/chromium/update')).status_code == 403
            # with CSRF succeeds
            ok = await c.post('/api/chromium/update', headers={'x-csrf-token': csrf})
            assert ok.status_code == 200 and ok.json()['ok'] is True
            assert ok.json()['status'] == STATUS_UP_TO_DATE
    finally:
        store.close()
