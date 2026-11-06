#!/usr/bin/env python3
"""One-command local QA gate. Never reports production-ready without runtime evidence.

Usage: python scripts/one_pass_qa.py --output validation/one_pass
Runs actual tests, rather than simply inspecting the source multiple times.
"""
from __future__ import annotations
import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLOCKERS = {
    "windows_executable_installer_signing": "BLOCKED: no Windows compiler, signed installer or live Windows execution in this environment",
    "enterprise_chrome_okta_target system": "BLOCKED: requires authorized Windows workstation, valid IT account and vendor-approved testing",
    "sqlcipher_windows_encryption_and_migration": "BLOCKED: native Windows SQLCipher, encrypted WAL/DPAPI and migration validation have not run",
    "recursive_workers_oopif": "PARTIAL: recursive capture implemented, but full real target lifecycle coverage is unverified",
    "browser_controller_survival": "PARTIAL PASS: real Chromium survives collector teardown/restart; browser-host process death remains a limitation",
    "safe_component_repair": "PARTIAL: bounded reattachment only, full repair contracts and fault matrix not complete",
    "optional_embedded_ai": "OPTIONAL: not bundled or verified fully offline",
    "full_t01_t50_soak_acceptance": "BLOCKED: full fault-injection, Windows 24h soak and acceptance matrix incomplete",
}



def run(cmd: list[str], *, environment: dict | None = None) -> dict:
    proc = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, errors="replace", env=environment)
    return {"command": cmd, "exit_code": proc.returncode,
            "status": "PASS" if proc.returncode == 0 else "FAIL", "output": proc.stdout[-30000:]}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument('--output', default='validation/one_pass')
    p.add_argument('--release', action='store_true', help='Fail if any release blocker remains')
    args = p.parse_args()
    out = (ROOT / args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment['COVERAGE_FILE'] = str(out / '.coverage')
    # Never create a plaintext production database through the QA runner;
    # the test-only backend still requires pytest context explicitly.
    environment['DIAGNOSTIC_BROWSER_TEST_PLAINTEXT'] = '1'
    checks = {
        'python_compilation':run([sys.executable,'-m','compileall','-q','diagnostic_browser','tests','scripts'],environment=environment),
        'full_pytest':run([sys.executable,'-m','pytest','-p','no:cacheprovider','-ra','-q','tests'],environment=environment),
        'coverage':run([sys.executable,'-m','coverage','run','--source','diagnostic_browser','-m','pytest','-p','no:cacheprovider','-q','tests'],environment=environment),
        'coverage_report':run([sys.executable,'-m','coverage','report','-m'],environment=environment),
    }
    if shutil.which('node'):
        checks['js_dashboard_syntax'] = run(['node','--check','diagnostic_browser/static/app.js'])
        checks['js_login_syntax'] = run(['node','--check','diagnostic_browser/static/login.js'])
    else:
        checks['javascript_syntax'] = {'status':'BLOCKED','reason':'Node.js missing'}
    local_ok = all(item.get('status')=='PASS' for item in checks.values())
    status = 'LOCAL_CHECKS_PASS__RELEASE_BLOCKED' if local_ok else 'LOCAL_CHECKS_FAIL'
    artifact = {'at_utc':datetime.now(timezone.utc).isoformat(),
                'version':'5.0.0rc4', 'status':status, 'release_ready':False,
                'local_checks':checks, 'release_blockers':BLOCKERS,
                'note':'A passed local suite does not certify production; SQLCipher Windows execution, Chrome/Okta/target system and complete worker coverage remain blocked.'}
    (out/'QA_RESULTS.json').write_text(json.dumps(artifact,indent=2),encoding='utf-8')
    (out/'QA_SUMMARY.md').write_text(
        '# Diagnostic Browser — independent local QA gate\n\n'
        f'Overall: **{status}**. Release ready: **NO**.\n\n'
        + '\n'.join(f'- {key}: {value["status"]}' for key,value in checks.items())
        + '\n\n## Mandatory runtime and architecture blockers\n\n'
        + '\n'.join(f'- {key}: {value}' for key,value in BLOCKERS.items())
        + '\n\nThe managed-policy Chromium navigation test is skipped in this environment. A separate real Chrome/CDP handshake smoke test is run and documented independently. '
          'Do not treat that skip as success.\n',encoding='utf-8')
    print(status)
    print(f'Wrote {out / "QA_RESULTS.json"}')
    if args.release:
        print('RELEASE GATE: BLOCKED (mandatory verification incomplete)')
        return 2
    return 0 if local_ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
