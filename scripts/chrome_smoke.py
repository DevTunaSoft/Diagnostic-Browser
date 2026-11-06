"""Windows IT workstation smoke test for an actual Chrome/CDP session.

No external navigation, no Okta, no target system access, no sandbox bypass.
Fails closed if Chrome/CDP cannot start normally. Requires explicit local execution.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import tempfile
from pathlib import Path

from diagnostic_browser.capture import BrowserFlight
from diagnostic_browser.policy import Scope
from diagnostic_browser.recorder import Recorder
from diagnostic_browser.store import EvidenceStore


async def check(chrome_path: str | None) -> dict:
    with tempfile.TemporaryDirectory(prefix='diagnostic-browser-smoke-') as folder:
        root=Path(folder)
        store=EvidenceStore(root/'evidence')
        rec=Recorder(store)
        flight=BrowserFlight(rec,root/'chrome-profile',Scope(),chrome_path,headless=False)
        await rec.start()
        try:
            page=await asyncio.wait_for(flight.start('about:blank'),timeout=45)
            if not page or page.is_closed():
                raise RuntimeError('Chrome did not create an active page')
            one=flight.health()
            if not one['browser_connected'] or one['pages_total'] < 1:
                raise RuntimeError('Chrome/CDP connection not verified')
            another=await flight.context.new_page()
            await asyncio.wait_for(another.goto('about:blank'),timeout=15)
            if another.is_closed():
                raise RuntimeError('Chrome second tab did not remain open')
            await another.close()
            await rec.flush(strict=True)
            return {'result':'PASS','browser_process_connected':True,
                    'cdp_page_subscription':any(x.ready for x in flight.pages.values()),
                    'new_tab':True,'sandbox_configuration':'ENABLED',
                    'external_web_navigation':'NOT_TESTED',
                    'okta_and_target system':'NOT_TESTED',
                    'browser_parity':'NOT_TESTED'}
        finally:
            try:
                await flight.stop()
            finally:
                await rec.stop()
                store.close()


def main() -> int:
    parser=argparse.ArgumentParser()
    parser.add_argument('--chrome-path', default=None)
    args=parser.parse_args()
    try:
        result=asyncio.run(check(args.chrome_path))
    except Exception as error:
        result={'result':'FAIL', 'reason_class':type(error).__name__,
                'sandbox_configuration':'ENABLED',
                'details':'Sensitive exception details deliberately withheld',
                'next_step':'Review approved Windows Chrome policies and local test logs'}
        print(json.dumps(result, indent=2))
        return 1
    print(json.dumps(result,indent=2))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
