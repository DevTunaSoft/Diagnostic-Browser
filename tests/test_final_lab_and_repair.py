"""Synthetic fault-lab and standalone repair fail-safe verification."""
from pathlib import Path
from unittest.mock import patch
import httpx
import pytest
from diagnostic_browser.lab import lab
from diagnostic_browser.repair import diagnose
from diagnostic_browser.store import EvidenceStore


@pytest.mark.asyncio
async def test_synthetic_lab_serves_errors_and_never_production_patient_data():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=lab),
                                 base_url='http://127.0.0.1') as client:
        home=await client.get('/')
        assert home.status_code==200
        assert 'Synthetic Fault Lab' in home.text
        assert 'FAKE_PASSWORD_SEED_91' in home.text
        failed=await client.get('/api/fail')
        assert failed.status_code==500
        assert 'FAKE_PATIENT_SEED_52' in failed.text
        forbidden=await client.get('/api/forbidden')
        assert forbidden.status_code==403
        assert 'fake token' in forbidden.text
        # These response bodies must never be collected by the browser recorder.


def test_standalone_repair_never_creates_missing_evidence_or_keys(tmp_path):
    root=tmp_path/'not-initialized'
    root.mkdir()
    result=diagnose(root,chrome_path='/nonexistent/chrome-for-test')
    assert result['database']=='NOT_INITIALIZED'
    assert result['encryption_key']=='MISSING'
    assert result['repairs_performed']==0
    assert not (root/'evidence.key').exists()
    assert not (root/'flight_recorder.sqlite').exists()


def test_standalone_repair_flags_orphaned_key_and_unknown_backend(tmp_path):
    root=tmp_path/'bad-evidence';root.mkdir()
    (root/'flight_recorder.sqlite').write_bytes(b'Not an encrypted database')
    with patch('diagnostic_browser.repair.EvidenceStore', side_effect=OSError('test failure')):
        result=diagnose(root)
    assert result['database']=='KEY_MISSING'
    assert result['repairs_performed']==0


def test_repair_read_only_verification_with_synthetic_store(tmp_path):
    # Production EvidenceStore requires Windows DPAPI and native SQLCipher.
    store=EvidenceStore(tmp_path,allow_test_plaintext=True)
    store.add('health','info',{'code':'READY','target':'collector'})
    store.close()
    from diagnostic_browser import repair
    original=repair.EvidenceStore
    repair.EvidenceStore=lambda root,read_only=False: original(root,read_only=read_only,allow_test_plaintext=True)
    try:
        result=repair.diagnose(tmp_path)
        assert result['database']=='PASS'
        assert result['encryption_key']=='AVAILABLE'
        assert result['approved_event_count']==1
        assert result['repairs_performed']==0
    finally:
        repair.EvidenceStore=original
