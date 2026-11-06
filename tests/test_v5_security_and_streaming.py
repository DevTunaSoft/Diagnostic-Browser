"""V5 security regressions; synthetic, no production credentials or websites."""
from __future__ import annotations
import json
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch
import pytest
from diagnostic_browser.store import EvidenceStore
from diagnostic_browser.reports import export_bundle


def test_production_fails_closed_without_cipher(monkeypatch, tmp_path):
    """No standard sqlite fallback can be accidentally used on a production path."""
    monkeypatch.setenv('DIAGNOSTIC_BROWSER_TEST_PLAINTEXT','1')
    import builtins
    orig = builtins.__import__
    def restrict(name,*args,**kwargs):
        if name == 'sqlcipher3' or name.startswith('sqlcipher3.'):
            raise ImportError('synthetic missing SQLCipher')
        return orig(name,*args,**kwargs)
    with patch('builtins.__import__',side_effect=restrict):
        with pytest.raises(RuntimeError,match='SQLCipher'):
            EvidenceStore(tmp_path)
    assert not (tmp_path/'flight_recorder.sqlite').exists()
    assert not (tmp_path/'evidence.key').exists()


def test_test_only_backend_requires_pytest_context(monkeypatch,tmp_path):
    monkeypatch.delenv('PYTEST_CURRENT_TEST',raising=False)
    with pytest.raises(RuntimeError,match='only during automated tests'):
        EvidenceStore(tmp_path,allow_test_plaintext=True)


def test_streamed_complete_export_does_not_call_store_events(tmp_path,monkeypatch):
    source=EvidenceStore(tmp_path,allow_test_plaintext=True)
    try:
        for i in range(5075):
            source.add('health','info',{'target':'collector','code':'READY','sequence':i})
        monkeypatch.setattr(source,'events',lambda *_args,**_kw: (_ for _ in ()).throw(AssertionError('unbounded events() called')))
        result=export_bundle(source,tmp_path/'export.zip')
        assert result['event_count']==5075
        with zipfile.ZipFile(result['path']) as z:
            records=z.read('03_Full_Event_Timeline.jsonl').splitlines()
            assert len(records)==5075
            manifest=json.loads(z.read('08_SHA256_Manifest.json'))
            assert manifest['event_count']==5075
            page=z.read('02_Offline_Interactive_Report.html')
            assert b'>5075</strong>' in page
            assert page.count(b'<tr>') == 5001
            pdf=z.read('01_Engineering_Report.pdf')
            assert pdf.startswith(b'%PDF-')
    finally: source.close()


def test_failed_export_does_not_overwrite_existing_evidence(tmp_path,monkeypatch):
    source=EvidenceStore(tmp_path,allow_test_plaintext=True)
    try:
        source.add('health','info',{'target':'collector','code':'READY'})
        dest=tmp_path/'archive.zip'; dest.write_bytes(b'EXISTING_PRESERVED_EVIDENCE')
        def fail(*args,**kwargs):
            raise OSError('simulated write interrupted')
        monkeypatch.setattr('diagnostic_browser.reports.build_pdf',fail)
        with pytest.raises(OSError):export_bundle(source,dest)
        assert dest.read_bytes()==b'EXISTING_PRESERVED_EVIDENCE'
        assert not list(tmp_path.glob('db-export-*.zip'))
    finally:source.close()
