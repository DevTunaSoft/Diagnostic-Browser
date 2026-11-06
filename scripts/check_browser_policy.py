#!/usr/bin/env python3
"""Non-invasive browser-policy preflight. Does not change or bypass policy."""
from __future__ import annotations
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from diagnostic_browser.environment_policy import inspect_local_policy


def main():
    p=argparse.ArgumentParser(description='Read-only enterprise browser access-policy preflight')
    p.add_argument('--output', default='validation/browser_policy_preflight.json')
    args=p.parse_args()
    status=inspect_local_policy()
    status['checked_utc']=datetime.now(timezone.utc).isoformat()
    status['recommended_next_step']=(
        'Request an approved Chrome enterprise policy allowlist or run browser '
        'acceptance on an authorized IT workstation; do not bypass policy.'
    )
    target=Path(args.output)
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(status,indent=2),encoding='utf-8')
    print(json.dumps(status,indent=2))
    return 0  # A policy restriction is an environment diagnosis, not a code defect.

if __name__=='__main__':raise SystemExit(main())
