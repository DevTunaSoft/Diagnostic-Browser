"""Regression tests for silent evidence loss, hung collectors and priority drops."""
import asyncio
from datetime import datetime, timezone
import threading
from uuid import uuid4
from unittest.mock import Mock
import pytest
from diagnostic_browser.browser_host import (
    _await_receipt, BrowserHostServer, HostRecorderProxy, MAX_PENDING,
)
from diagnostic_browser.recorder import Recorder
from diagnostic_browser.store import EvidenceStore

class StallConnection:
    def __init__(self):
        self.count=0
    def poll(self, timeout):
        self.count+=1
        return False

class GoodConnection:
    def __init__(self, ack): self.ack=ack
    def poll(self, timeout): return True
    def recv_bytes(self, max_length): return self.ack.encode('ascii')

def test_host_ack_is_bounded_and_not_assumed_from_connection_state():
    conn=StallConnection()
    with pytest.raises(ConnectionError,match='timed out'):
        _await_receipt(conn,uuid4().hex,threading.Event(),timeout=.025)
    assert conn.count>0
    pending=HostRecorderProxy()
    assert pending.accept('health','info',{'code':'READY'})
    assert pending.size()==1  # a stalled collector cannot discard the event

def test_host_ack_is_exact_and_shutdown_interrupts_stalled_receipt():
    ref=uuid4().hex
    _await_receipt(GoodConnection(ref),ref,threading.Event())
    with pytest.raises(ConnectionError,match='mismatch'):
        _await_receipt(GoodConnection(uuid4().hex),ref,threading.Event())
    stop=threading.Event(); stop.set()
    with pytest.raises(ConnectionError,match='stopping'):
        _await_receipt(StallConnection(),ref,stop)


def test_critical_evidence_displaces_only_low_priority_activity():
    proxy=HostRecorderProxy()
    assert proxy.accept('http_activity','info',{'status':200,'method':'GET','route':'api'})
    first=proxy.next()['event_ref']
    for _ in range(MAX_PENDING-1):
        assert proxy.accept('http_activity','info',{'status':200,'method':'GET','route':'api'})
    assert proxy.accept('js_exception','error',{'error_class':'TypeError'})
    assert proxy.size()==MAX_PENDING
    assert proxy.next()['event_ref']==first  # in-flight receipt never discarded
    assert proxy.events[-1]['kind']=='js_exception'
    assert proxy.stats['priority_replaced']==1
    assert proxy.stats['queue_full']==1


def test_overloaded_queue_does_not_discard_existing_critical_evidence():
    proxy=HostRecorderProxy()
    for _ in range(MAX_PENDING):
        assert proxy.accept('js_exception','error',{'error_class':'TypeError'})
    assert not proxy.accept('browser_crash','critical',{'target':'page','reason':'crash'})
    assert proxy.stats['queue_full']==1
    assert proxy.size()==MAX_PENDING


@pytest.mark.asyncio
async def test_invalid_event_is_rejected_without_false_durable_ack(tmp_path):
    store=EvidenceStore(tmp_path,allow_test_plaintext=True)
    recorder=Recorder(store)
    await recorder.start()
    server=BrowserHostServer(tmp_path,recorder,store)
    server.loop=asyncio.get_running_loop()
    try:
        bad={'op':'event','event_ref':uuid4().hex,
             'observed_at':datetime.now(timezone.utc).isoformat(),
             'kind':'health','severity':'info','fields':{'password':'LEAK_TEST'}}
        # A rejected event is acknowledged only AFTER the privacy-exclusion
        # loss receipt is durably recorded. No secret fields are stored.
        await asyncio.to_thread(server._dispatch,bad)
        assert store.count()==0
        assert store.losses()[0]['reason']=='POLICY_EXCLUDED'
        assert 'LEAK_TEST' not in str(store.losses())
        await asyncio.to_thread(server._dispatch,bad)
        assert len(store.losses())==1  # same stable ID, idempotent replay
    finally:
        await recorder.stop()
        store.close()


@pytest.mark.asyncio
async def test_coverage_commit_failure_does_not_ack_or_claim_success(tmp_path):
    store=EvidenceStore(tmp_path,allow_test_plaintext=True)
    rec=Recorder(store);await rec.start()
    server=BrowserHostServer(tmp_path,rec,store)
    server.loop=asyncio.get_running_loop()
    original=store.set_coverage
    def broken(*a): raise OSError('synthetic write error')
    store.set_coverage=broken
    try:
        # _dispatch blocks while it waits for a callback on this loop;
        # execute it in a worker thread like the real IPC listener does.
        with pytest.raises(ConnectionError,match='not committed'):
            await asyncio.to_thread(server._dispatch,{'op':'coverage',
                                     'source':'page:12345','state':'ACTIVE'})
        assert server.received==0
        store.set_coverage=original
        await asyncio.to_thread(server._dispatch,{'op':'coverage',
                                       'source':'page:12345','state':'ACTIVE'})
        assert any(item['source']=='page:12345' and item['state']=='ACTIVE' for item in store.coverage())
    finally:
        store.set_coverage=original
        await rec.stop();store.close()

@pytest.mark.asyncio
async def test_bridge_ping_is_validated_without_generating_fake_evidence(tmp_path):
    store=EvidenceStore(tmp_path,allow_test_plaintext=True)
    recorder=Recorder(store);await recorder.start()
    server=BrowserHostServer(tmp_path,recorder,store)
    server.loop=asyncio.get_running_loop()
    try:
        server._dispatch({'op':'ping','event_ref':uuid4().hex})
        assert server.received==1
        assert store.count()==0
        for bad in ({'op':'ping','event_ref':'invalid'},
                    {'op':'unknown','event_ref':uuid4().hex},
                    {'op':'ping','event_ref':uuid4().hex,'password':'SECRET'}):
            with pytest.raises(ValueError):server._dispatch(bad)
        assert store.count()==0
    finally:
        await recorder.stop();store.close()
