"""Publication must never be inferred from partial or malformed evidence."""
import importlib.util
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / 'scripts' / 'publication_gate.py'
spec = importlib.util.spec_from_file_location('publication_gate', FILE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def test_empty_evidence_blocks():
    report = mod.evaluate(None, {})
    assert report['publication'] == 'BLOCKED'
    assert set(report['checks'].values()) == {'BLOCKED'}

def test_fake_pass_does_not_count(tmp_path):
    exe = tmp_path / 'DiagnosticBrowser.exe'
    exe.write_bytes(b'not a real exe')
    evidence = {k: {'result': 'PASS', 'proof': 'verified'} for k in mod.CHECKS}
    assert mod.evaluate(exe, evidence)['publication'] == 'BLOCKED'
    evidence['exe_sha256'] = 'incorrect'
    assert mod.evaluate(exe, evidence)['publication'] == 'BLOCKED'

def test_missing_proof_blocks(tmp_path):
    exe = tmp_path / 'DiagnosticBrowser.exe'
    exe.write_bytes(b'placeholder')
    evidence = {k: {'result': 'PASS', 'proof': ' '} for k in mod.CHECKS}
    evidence['exe_sha256'] = mod.sha256(exe)
    assert all(v == 'BLOCKED' for v in mod.evaluate(exe, evidence)['checks'].values())

def test_all_checks_need_evidence(tmp_path):
    exe = tmp_path / 'DiagnosticBrowser.exe'
    exe.write_bytes(b'placeholder')
    evidence = {k: {'result': 'PASS', 'proof': 'artifact reference'} for k in mod.CHECKS}
    evidence['exe_sha256'] = mod.sha256(exe)
    assert mod.evaluate(exe, evidence)['publication'] == 'APPROVED'
    del evidence['authorized_workflow']
    assert mod.evaluate(exe, evidence)['publication'] == 'BLOCKED'
