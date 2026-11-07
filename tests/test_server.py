import pytest
from httpx import AsyncClient,ASGITransport
from diagnostic_browser.store import EvidenceStore
from diagnostic_browser.recorder import Recorder
from diagnostic_browser.server import Dashboard

@pytest.mark.asyncio
async def test_dashboard_auth_csrf_export_and_selftest(tmp_path):
    store=EvidenceStore(tmp_path, allow_test_plaintext=True);rec=Recorder(store);await rec.start()
    d=Dashboard(store,rec,tmp_path)
    async with AsyncClient(transport=ASGITransport(app=d.app),base_url='http://127.0.0.1:18731') as client:
        assert (await client.get('/api/status')).status_code==401
        assert (await client.post('/api/login',json={'code':'wrong'})).status_code==401
        assert (await client.post('/api/login',json={'code':d.login_code})).status_code==200
        csrf=(await client.get('/api/session')).json()['csrf']
        assert (await client.post('/api/incidents')).status_code==403
        headers={'X-CSRF-Token':csrf}
        assert (await client.post('/api/incidents',headers=headers)).status_code==200
        result=(await client.post('/api/self-test',headers=headers)).json()
        assert result['collector_delivery'] and result['database_integrity']
        x=(await client.post('/api/export',json={'preset':'engineering'},headers=headers))
        assert x.status_code==200,x.text
        assert x.json()['event_count']>=2
        assert (await client.get('/api/export/file/'+x.json()['filename'])).content[:2]==b'PK'
        assert (await client.post('/api/export',json={'preset':'../some'},headers=headers)).status_code==422
        assert (await client.get('/api/status',headers={'Origin':'https://evil.example'})).status_code==403
    await rec.stop();store.close()


@pytest.mark.asyncio
async def test_dashboard_home_serves_unicode_utf8(tmp_path):
    # Regression: home() must read the static HTML as UTF-8. The dashboard uses
    # non-ASCII icons; on a cp1252 default (Windows) an unspecified encoding
    # raised UnicodeDecodeError and every dashboard load 500-errored.
    from pathlib import Path
    static=Path('diagnostic_browser/static')
    for name in ('index.html','login.html'):
        (static/name).read_bytes().decode('utf-8')  # both must be valid UTF-8
    # index.html contains bytes undefined in cp1252, so an unspecified read on a
    # cp1252-default host would raise - this is exactly what broke on Windows.
    idx=(static/'index.html').read_bytes()
    try:
        idx.decode('cp1252'); cp1252_ok=True
    except UnicodeDecodeError:
        cp1252_ok=False
    assert not cp1252_ok, 'index.html should force an explicit UTF-8 read'
    store=EvidenceStore(tmp_path, allow_test_plaintext=True);rec=Recorder(store);await rec.start()
    d=Dashboard(store,rec,tmp_path)
    async with AsyncClient(transport=ASGITransport(app=d.app),base_url='http://127.0.0.1:18731') as client:
        login=(await client.get('/')); assert login.status_code==200 and len(login.text)>0
        await client.post('/api/login',json={'code':d.login_code})
        home=(await client.get('/'))
        assert home.status_code==200 and '◈' in home.text
    await rec.stop();store.close()
