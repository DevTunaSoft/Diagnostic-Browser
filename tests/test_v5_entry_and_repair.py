"""Entry, standalone recovery and process fault tests (no live websites)."""
import json
import sys
from pathlib import Path
from unittest.mock import patch
import pytest
from diagnostic_browser import main as launcher
from diagnostic_browser.repair import diagnose
from diagnostic_browser.watchdog import run as watchdog_run


def test_read_only_repair_does_not_create_an_evidence_database(tmp_path):
    result=diagnose(tmp_path,chrome_path=str(tmp_path/'nonexistent.exe'))
    assert result['database']=='NOT_INITIALIZED'
    assert result['repairs_performed']==0
    assert not (tmp_path/'flight_recorder.sqlite').exists()
    assert not (tmp_path/'evidence.key').exists()


def test_read_only_repair_blocks_missing_key_without_creating_key(tmp_path):
    (tmp_path/'flight_recorder.sqlite').write_bytes(b'SQLite format 3\0' + b'0'*100)
    result=diagnose(tmp_path,chrome_path=str(tmp_path/'nonexistent.exe'))
    assert result['database']=='KEY_MISSING'
    assert not (tmp_path/'evidence.key').exists()


def test_main_rejects_reentrant_instance_before_browser(tmp_path,monkeypatch):
    called=[]
    async def fake_run(args):called.append(args.data_dir)
    monkeypatch.setattr(launcher,'run',fake_run)
    monkeypatch.setattr(sys,'argv',['diagnostic-browser','--engine','--data-dir',str(tmp_path),'--url','about:blank'])
    launcher.main()
    assert called==[str(tmp_path)]
    assert (tmp_path/'diagnostic_browser.instance.lock').exists()


def test_watchdog_independent_process_writes_local_start_receipt(tmp_path):
    report=tmp_path/'watchdog.jsonl'
    stop=tmp_path/'stop';stop.touch()
    watchdog_run(tmp_path/'missing_heartbeat',report,stop,123,interval=0.001)
    lines=report.read_text().splitlines()
    assert lines
    assert json.loads(lines[0])['code']=='WATCHDOG_STARTED'
    assert 'cookie' not in report.read_text().lower()
