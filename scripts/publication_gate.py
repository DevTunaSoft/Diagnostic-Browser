"""Fail-closed publication gate: source validation is NOT a Windows runtime pass.

The report can be populated only by explicit artifacts and independently recorded
acceptance. Missing evidence is BLOCKED, never implicitly successful.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

CHECKS = (
    'single_file_exe', 'embedded_chromium', 'embedded_offline_ai',
    'native_sqlcipher_dpapi', 'clean_windows_launch', 'browser_navigation',
    'authorized_workflow', 'flight_recorder_incident', 'crash_recovery',
    'exports_privacy', 'windows_24h_soak', 'code_signing',
    'unified_browser_gui', 'enterprise_security_review',
)

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def evaluate(exe: Path | None, evidence: dict) -> dict:
    """Only literal PASS plus nonempty evidence qualifies; never infer a pass."""
    checks = {}
    for name in CHECKS:
        entry = evidence.get(name)
        valid = (isinstance(entry, dict) and entry.get('result') == 'PASS'
                 and isinstance(entry.get('proof'), str) and bool(entry['proof'].strip()))
        checks[name] = 'PASS' if valid else 'BLOCKED'
    if exe is None or not exe.is_file() or exe.suffix.lower() != '.exe':
        checks['single_file_exe'] = 'BLOCKED'
    elif evidence.get('exe_sha256') != sha256(exe):
        checks['single_file_exe'] = 'BLOCKED'
    return {'publication': 'APPROVED' if all(v == 'PASS' for v in checks.values()) else 'BLOCKED',
            'checks': checks, 'exe_sha256': sha256(exe) if exe and exe.is_file() else None}

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument('--exe', type=Path)
    p.add_argument('--evidence', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    try:
        evidence = json.loads(args.evidence.read_text(encoding='utf-8'))
        if not isinstance(evidence, dict):
            raise ValueError('evidence must be an object')
    except (OSError, ValueError) as e:
        evidence = {'_error': str(e)}
    result = evaluate(args.exe, evidence)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
    return 0 if result['publication'] == 'APPROVED' else 1

if __name__ == '__main__':
    raise SystemExit(main())
