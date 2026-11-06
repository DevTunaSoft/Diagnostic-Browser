#!/usr/bin/env python3
"""Generate reproducible local-only, synthetic support bundle. Never live data."""
import os
import tempfile
import zipfile
import argparse
import shutil
from pathlib import Path
from diagnostic_browser.store import EvidenceStore
from diagnostic_browser.reports import export_bundle


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--synthetic-only',action='store_true')
    args=parser.parse_args()
    if not args.synthetic_only:
        parser.error('--synthetic-only required; not for real evidence')
    args.output.mkdir(parents=True,exist_ok=True)
    os.environ['DIAGNOSTIC_BROWSER_TEST_PLAINTEXT']='1'
    os.environ['PYTEST_CURRENT_TEST']='synthetic-demo-fixture'
    with tempfile.TemporaryDirectory(prefix='v5-synthetic-') as tmp:
        store=EvidenceStore(Path(tmp),allow_test_plaintext=True)
        try:
            for n in range(140):
                store.add('http_activity','info',{'method':'GET','status':200,
                          'route':'api','resource':'XHR','sequence':n})
            for n in range(8):
                store.add('network_failure','error',{'error_code':'ERR_CONNECTION_RESET',
                           'route':'socket.io','request_ref':f'{n+1000:032x}'})
            for n in range(4):
                store.add('js_exception','error',{'error_class':'TypeError','line':42,'column':8})
            store.mark('manual')
            store.set_coverage('page:synthetic','ACTIVE')
            store.set_coverage('worker:synthetic','UNSUPPORTED')
            result=export_bundle(store,args.output/'Diagnostic_Browser_V5_SYNTHETIC_Engineering_Bundle.zip',
                                 health={'demo':'SYNTHETIC','network_used':False})
            with zipfile.ZipFile(result['path']) as archive:
                (args.output/'Diagnostic_Browser_V5_SYNTHETIC_Report.pdf').write_bytes(archive.read('01_Engineering_Report.pdf'))
                (args.output/'Diagnostic_Browser_V5_SYNTHETIC_Offline_Report.html').write_bytes(archive.read('02_Offline_Interactive_Report.html'))
            print('SYNTHETIC ONLY, events:',result['event_count'])
        finally:store.close()

if __name__=='__main__':main()
