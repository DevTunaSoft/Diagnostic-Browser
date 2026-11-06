"""One-file build contracts, child isolation and model privacy regression tests."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, AsyncMock
import asyncio
import os
import pytest
from diagnostic_browser import bundle, offline_ai
from diagnostic_browser.capture import BrowserFlight
from diagnostic_browser.policy import Scope
ROOT=Path(__file__).resolve().parents[1]


def test_onefile_builder_embeds_required_subsystems():
    text=(ROOT/'scripts/build_single_exe_windows.ps1').read_text().lower()
    for required in ('--onefile','--collect-all playwright','--collect-all sqlcipher3',
                     '--collect-all llama_cpp','playwright install chromium','--verify-bundle','get-filehash'):
        assert required in text
    assert '--onedir' not in text
    assert (ROOT/'scripts/validate_onefile_clean_windows.ps1').exists()


def test_frozen_config_forces_bundled_browser(monkeypatch):
    monkeypatch.setattr(bundle,'is_frozen',lambda:True)
    monkeypatch.delenv('PLAYWRIGHT_BROWSERS_PATH',raising=False)
    bundle.configure_bundled_browser()
    assert os.environ['PLAYWRIGHT_BROWSERS_PATH']=='0'


def test_missing_and_tampered_model_fail_closed(monkeypatch,tmp_path):
    monkeypatch.setattr(bundle,'is_frozen',lambda:True)
    monkeypatch.setattr(bundle,'bundled_browser_path',lambda:tmp_path)
    m=tmp_path/'test.gguf'
    monkeypatch.setattr(bundle,'model_path',lambda:m)
    with pytest.raises(RuntimeError,match='missing'):
        bundle.verify_bundled_runtime()
    m.write_bytes(b'GGUF'+b'A'*1048576)
    with pytest.raises(RuntimeError,match='SHA-256'):
        bundle.verify_bundled_runtime()


def test_frozen_browser_rejects_external_chrome(monkeypatch,tmp_path):
    monkeypatch.setattr(bundle,'is_frozen',lambda:True)
    flight=BrowserFlight(SimpleNamespace(),tmp_path,Scope(allowed_hosts=('example.org','api.example.org','a.b.example.org','a.example.org','app.example.org','portal.example.org','dispatch.example.org')),chrome_path='C:/Chrome/chrome.exe')
    fake=SimpleNamespace(chromium=SimpleNamespace(launch_persistent_context=AsyncMock()))
    class PW:
        async def start(self):return fake
    with patch('diagnostic_browser.capture.async_playwright',lambda:PW()):
        with pytest.raises(RuntimeError,match='External Chrome'):
            asyncio.run(flight.start())
    fake.chromium.launch_persistent_context.assert_not_awaited()


def test_ai_removes_planted_secrets_and_caps_events():
    data=[{'kind':'health','severity':'info','fields':{'code':'READY'}} for _ in range(100)]
    data += [{'kind':'health','severity':'info','fields':{'password':'PRIVATE_CANARY'}},
             {'kind':'health','severity':'info','fields':{'cookie':'SECRET_CANARY'}}]
    assert len(offline_ai.sanitized_snapshot(data))==38
    prompt=offline_ai.build_prompt(data)
    assert 'PRIVATE_CANARY' not in prompt and 'SECRET_CANARY' not in prompt
    assert 'READY' in prompt
    with pytest.raises(ValueError):offline_ai.sanitized_snapshot({'prompt':'fake'})


def test_ai_without_model_never_falls_back_to_cloud(monkeypatch,tmp_path):
    monkeypatch.setattr(offline_ai,'model_path',lambda:tmp_path/'missing.gguf')
    with pytest.raises(RuntimeError,match='offline AI model unavailable'):
        offline_ai.infer([])


def test_ai_local_model_mock_no_gpu_no_raw_data(monkeypatch,tmp_path):
    m=tmp_path/'test.gguf';m.write_bytes(b'GGUF'+b'B'*1048576)
    monkeypatch.setattr(offline_ai,'model_path',lambda:m)
    class Model:
        def __init__(self,**opts):
            assert opts['n_gpu_layers']==0 and opts['model_path']==str(m)
        def create_completion(self,**opts):
            assert 'TOPSECRET' not in opts['prompt']
            return {'choices':[{'text':'Observed evidence; not a verified cause.'}]}
    events=[{'kind':'health','severity':'warning','fields':{'code':'READY'}},
            {'kind':'health','severity':'info','fields':{'token':'TOPSECRET'}}]
    assert 'not a verified cause' in offline_ai.infer(events,model_factory=Model)


def test_onefile_detached_children_get_independent_lifetime(monkeypatch):
    from diagnostic_browser import supervisor
    observed=[]
    monkeypatch.setattr(supervisor.sys,'frozen',True,raising=False)
    monkeypatch.setattr(supervisor.subprocess,'Popen',lambda cmd,**kw: observed.append(kw))
    supervisor.spawn_engine(['DiagnosticBrowser.exe','--engine'])
    assert observed[0]['env']['PYINSTALLER_RESET_ENVIRONMENT']=='1'
    host=(ROOT/'diagnostic_browser/browser_host.py').read_text()
    assert "'PYINSTALLER_RESET_ENVIRONMENT': '1'" in host
