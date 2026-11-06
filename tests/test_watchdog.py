import threading
import time
import json
import os
from diagnostic_browser.watchdog import run

def test_watchdog_reports_lost_and_restored_heartbeat(tmp_path):
    heartbeat=tmp_path/'hb';report=tmp_path/'wd.jsonl';stop=tmp_path/'stop'
    heartbeat.write_text('healthy')
    old=time.time()-20
    os.utime(heartbeat,(old,old))
    thread=threading.Thread(target=run,args=(heartbeat,report,stop,0,0.08,0.6))
    thread.start()
    try:
        until=time.monotonic()+3
        while time.monotonic()<until:
            if report.exists() and 'COLLECTOR_HEARTBEAT_STALE' in report.read_text():break
            time.sleep(0.03)
        heartbeat.touch()
        until=time.monotonic()+3
        while time.monotonic()<until:
            if report.exists() and 'COLLECTOR_HEARTBEAT_RECOVERED' in report.read_text():break
            time.sleep(0.03)
    finally:
        stop.touch();thread.join(timeout=3)
    codes=[json.loads(x)['code'] for x in report.read_text().splitlines()]
    assert 'COLLECTOR_HEARTBEAT_STALE' in codes
    assert 'COLLECTOR_HEARTBEAT_RECOVERED' in codes
