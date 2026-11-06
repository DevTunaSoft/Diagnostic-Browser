#!/usr/bin/env python3
"""Real browser/CDP handshake smoke test, with NO website navigation.

Run in an authorized interactive user session. This test intentionally does not
remove Chrome sandboxing or enterprise policies and does not use live credentials.
It validates the diagnostic attachment, NOT target system or Okta compatibility.
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


async def probe(chrome_path: str | None) -> dict:
    with tempfile.TemporaryDirectory(prefix='diagnostic-browser-chrome-smoke-') as directory:
        root = Path(directory)
        store = EvidenceStore(root / 'evidence')
        recorder = Recorder(store, auto_incident=False)
        flight = BrowserFlight(recorder, root / 'chrome-profile', Scope(), chrome_path)
        await recorder.start()
        try:
            page = await flight.start('about:blank')
            health = flight.health()
            if not health['browser_connected'] or page not in flight.pages:
                raise RuntimeError('browser controller not connected')
            if not flight.pages[page].ready:
                raise RuntimeError('CDP diagnostics not armed')
            result = await flight.pages[page].session.send('Browser.getVersion')
            if not isinstance(result.get('product'), str) or not result['product']:
                raise RuntimeError('browser version not available')
            return {'status': 'PASS', 'browser': result['product'],
                    'cdp_armed': True, 'browser_connected': True,
                    'initial_page': 'about:blank',
                    'navigation_tested': False, 'authentication_tested': False,
                    'windows_tested': __import__('sys').platform == 'win32'}
        finally:
            await flight.stop()
            await recorder.stop()
            store.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--chrome-path', default=None,
                        help='Explicit installed Chrome/Chromium executable path')
    args = parser.parse_args()
    result = asyncio.run(probe(args.chrome_path))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
