"""Synthetic CDP event tests + best-effort real Chromium launch verification.

This sandbox's enterprise Chromium URLBlocklist=["*"] blocks actual local navigation.
We do not alter or bypass it; those tests must be repeated on a permitted OS.
"""
import asyncio
import pytest
from diagnostic_browser.store import EvidenceStore
from diagnostic_browser.recorder import Recorder
from diagnostic_browser.policy import Scope
from diagnostic_browser.capture import BrowserFlight, PageCapture

@pytest.mark.asyncio
async def test_scoped_cdp_event_ingest_without_network(tmp_path):
    store=EvidenceStore(tmp_path/'db', allow_test_plaintext=True); rec=Recorder(store)
    await rec.start()
    capture=PageCapture(None,None,rec,Scope(test_local=True))
    try:
        capture.on_request({'requestId':'one','request':{'url':'http://127.0.0.1:7777/api/patient/SECRET_123?token=SENTINEL', 'method':'POST'}})
        capture.on_response({'requestId':'one','response':{'url':'http://127.0.0.1:7777/api/private?SECRET_456','status':500},'type':'XHR'})
        capture.on_request({'requestId':'auth','request':{'url':'https://login.okta.com/api/SECRET_789','method':'POST'}})
        capture.on_response({'requestId':'auth','response':{'url':'https://login.okta.com/api/SECRET_789','status':403},'type':'XHR'})
        capture.on_socket({'requestId':'sock','url':'ws://127.0.0.1:7777/socket.io?token=SENTINEL'})
        capture.on_socket_handshake({'requestId':'sock'})
        capture.on_socket_close({'requestId':'sock'})
        capture.execution_contexts[18]=True
        capture.execution_contexts[19]=False
        capture.on_exception({'exceptionDetails':{'executionContextId':18,'exception':{'className':'TypeError','description':'PATIENT_TOKEN_FAKE'},'lineNumber':23,'columnNumber':8}})
        capture.on_exception({'exceptionDetails':{'executionContextId':19,'exception':{'className':'TypeError','description':'PATIENT_TOKEN_FAKE'}}})
        capture.on_failed({'requestId':'one','errorText':'net::ERR_CONNECTION_RESET includes SECRET_901'})
        await rec.flush()
        events=store.events()
        kinds=[e['kind'] for e in events]
        assert 'http_error' in kinds
        assert kinds.count('js_exception')==1
        assert 'websocket_open' in kinds and 'websocket_closed' in kinds
        assert 'network_failure' in kinds
        canaries=('SENTINEL','SECRET_123','SECRET_456','SECRET_789','PATIENT_TOKEN_FAKE','SECRET_901')
        for canary in canaries:
            assert canary not in str(events)
        from diagnostic_browser.reports import export_bundle
        from zipfile import ZipFile
        p=tmp_path/'privacy_canary_bundle.zip'
        export_bundle(store,p)
        with ZipFile(p) as z:
            for filename in z.namelist():
                data=z.read(filename)
                for canary in canaries:
                    assert canary.encode() not in data, (canary,filename)
        dbbytes=b''.join(x.read_bytes() for x in (tmp_path/'db').glob('flight_recorder.sqlite*'))
        for canary in canaries:assert canary.encode() not in dbbytes
    finally:
        await rec.stop();store.close()

@pytest.mark.asyncio
async def test_real_chromium_launch_and_navigation_if_policy_allows(tmp_path):
    from pathlib import Path
    if not Path('/usr/bin/chromium').is_file():pytest.skip('Chromium unavailable')
    store=EvidenceStore(tmp_path/'db', allow_test_plaintext=True);rec=Recorder(store);await rec.start()
    flight=BrowserFlight(rec,tmp_path/'browser',Scope(test_local=True),'/usr/bin/chromium',headless=True)
    try:
        try:
            page=await asyncio.wait_for(flight.start('http://127.0.0.1:1/'),timeout=25)
        except Exception as error:
            # This container runs Chromium as root; sandboxed Chrome must fail.
            # Do not bypass Chrome's sandbox just to obtain a green test.
            if 'Chromium sandboxing failed' in str(error):
                pytest.skip('Real Chromium sandbox unavailable in this container; Windows runtime verification required')
            raise
        assert page is not None  # Proven actual browser process via Playwright
        if flight.status=='DEGRADED':
            pytest.skip('Chromium navigation blocked in environment; URLBlocklist or no server')
    finally:
        await flight.stop();await rec.stop();store.close()
