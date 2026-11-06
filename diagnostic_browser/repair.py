"""Standalone non-destructive repair-mode diagnostics; independent of dashboard startup."""
from __future__ import annotations
import argparse
import json
import os
import shutil
from pathlib import Path
from datetime import datetime,timezone
from .store import EvidenceStore

def diagnose(root:Path,chrome_path:str|None=None)->dict:
    result={'checked_utc':datetime.now(timezone.utc).isoformat(),'mode':'non_destructive_repair_diagnostics',
            'database':'NOT_CHECKED','encryption_key':'NOT_CHECKED','chrome':'NOT_CHECKED',
            'repairs_performed':0,'limitations':['Does not modify browser profile or Windows security policies.']}
    try:
        if (root/'evidence.key').exists() and (root/'flight_recorder.sqlite').is_file():
            store=EvidenceStore(root,read_only=True)
            try:
                result['encryption_key']='AVAILABLE'
                result['database']='PASS' if store.integrity() else 'FAIL'
                result['approved_event_count']=store.count()
                # Decrypt one record if present, to catch wrong keys or corruption.
                if store.count(): store.recent_events(1)
            finally:store.close()
        else:
            result['encryption_key']='MISSING'
            result['database']='NOT_INITIALIZED' if not (root/'flight_recorder.sqlite').exists() else 'KEY_MISSING'
    except Exception:
        result['encryption_key']='UNAVAILABLE_OR_INVALID'
        result['database']='FAIL'
    if getattr(__import__('sys'), 'frozen', False):
        try:
            from .bundle import bundled_browser_path
            bundled_browser_path()
            result['chrome'] = 'BUNDLED'
        except Exception:
            result['chrome'] = 'MISSING_BUNDLED'
        return result
    chosen=chrome_path or shutil.which('chrome') or shutil.which('google-chrome') or shutil.which('chromium')
    if not chosen and os.name == 'nt':
        for candidate in (Path(os.environ.get('PROGRAMFILES','C:/Program Files'))/'Google/Chrome/Application/chrome.exe',
                          Path(os.environ.get('PROGRAMFILES(X86)','C:/Program Files (x86)'))/'Google/Chrome/Application/chrome.exe'):
            if candidate.is_file():
                chosen=str(candidate);break
    result['chrome']='FOUND' if chosen and Path(chosen).is_file() else 'NOT_FOUND'
    return result

def main():
    parser=argparse.ArgumentParser(description='Diagnostic Browser independent health/repair diagnostic')
    default=Path(os.environ.get('LOCALAPPDATA',str(Path.home()/'.local'/'share')))/'DiagnosticBrowser'
    parser.add_argument('--data-dir',default=str(default));parser.add_argument('--chrome-path')
    args=parser.parse_args()
    report=diagnose(Path(args.data_dir),args.chrome_path)
    print(json.dumps(report,indent=2))
    return 0 if report['database'] in ('PASS','NOT_INITIALIZED') else 1

if __name__=='__main__':raise SystemExit(main())
