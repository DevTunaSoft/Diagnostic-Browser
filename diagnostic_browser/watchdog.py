"""Independent process checking the collector heartbeat and published recorder health.

The watchdog has no Chrome/CDP authorization and never restarts an authenticated
browser. Only fixed, non-sensitive diagnostic codes are persisted.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path


def parent_alive(pid: int) -> bool | None:
    """Return True/False/Unknown without ever signaling a Windows process.

    os.kill(pid, 0) is suitable on POSIX; on Windows use a read-only process
    handle and its exit status. Unknown permissions must not be reported as dead.
    """
    if pid <= 0:
        return None
    if os.name != 'nt':
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return None
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    # Request only synchronization and limited query rights, never termination.
    handle = kernel.OpenProcess(0x00100000 | 0x1000, False, pid)
    if not handle:
        # Access denied => unknown, invalid PID => terminated.
        return False if ctypes.get_last_error() == 87 else None
    try:
        result = kernel.WaitForSingleObject(handle, 0)
        if result == 0:  # WAIT_OBJECT_0: process terminated
            return False
        if result == 258:  # WAIT_TIMEOUT: still running
            return True
        return None
    finally:
        kernel.CloseHandle(handle)



def _emit(report: Path, code: str) -> None:
    line = json.dumps({'at': datetime.now(timezone.utc).isoformat(),
                       'code': code, 'watchdog': 'independent'})
    with report.open('a', encoding='utf-8') as file:
        file.write(line + '\n')
        file.flush()
        os.fsync(file.fileno())


def run(heartbeat: Path, report: Path, stop: Path, parent_pid: int,
        interval: float = 2.0, stale: float = 8.0):
    report.parent.mkdir(parents=True, exist_ok=True)
    last_stale = None
    last_degraded = None
    last_browser_degraded = None
    last_dashboard_degraded = None
    verified_heartbeat = False
    health_file = report.with_suffix('.health.json')
    _emit(report, 'WATCHDOG_STARTED')
    while not stop.exists():
        try:
            stat = heartbeat.stat()
            age = time.time() - stat.st_mtime
            is_stale = not (-5.0 <= age <= stale)
            if is_stale is False:
                if stat.st_size > 4096:
                    raise ValueError('malformed collector heartbeat')
                payload = heartbeat.read_text(encoding='utf-8')
                try:
                    obj = json.loads(payload)
                    if not isinstance(obj, dict):
                        raise ValueError('heartbeat is not an object')
                    # Check the components independently. An unknown browser
                    # state must not erase a proven recorder failure.
                    recorder_state = obj.get('recorder_state')
                    state = obj.get('browser_state')
                    if (recorder_state in {'INITIALIZING', 'ARMED', 'RECORDING',
                        'PAUSED', 'DEGRADED', 'RECOVERING', 'FAILED', 'STOPPED'}
                        and isinstance(obj.get('writer_running'), bool)):
                        is_degraded = (recorder_state not in ('ARMED', 'RECORDING')
                                       or obj['writer_running'] is not True)
                    else:
                        is_degraded = None
                        last_degraded = None
                    if (state in {'INITIALIZING', 'ARMED', 'RECORDING',
                                  'PAUSED', 'DEGRADED', 'RECOVERING', 'FAILED', 'STOPPED'}
                        and isinstance(obj.get('browser_connected'), bool)):
                        is_browser_degraded = (state not in ('ARMED', 'RECORDING')
                                               or obj['browser_connected'] is not True)
                    else:
                        is_browser_degraded = None
                        last_browser_degraded = None
                    dashboard_state = obj.get('dashboard_state')
                    dashboard_degraded = (dashboard_state != 'RUNNING') if dashboard_state in ('RUNNING', 'STARTING', 'FAILED') else None
                    verified_heartbeat = True
                except (ValueError, TypeError, AttributeError):
                    # Malformed heartbeats never establish component health.
                    verified_heartbeat = False
                    is_degraded = None
                    is_browser_degraded = None
                    last_degraded = None
                    last_browser_degraded = None
                    dashboard_degraded = None
                    last_dashboard_degraded = None
                if is_browser_degraded is not None and is_browser_degraded != last_browser_degraded:
                    _emit(report, 'BROWSER_DEGRADED' if is_browser_degraded else 'BROWSER_OBSERVED')
                    last_browser_degraded = is_browser_degraded
                if dashboard_degraded is not None and dashboard_degraded != last_dashboard_degraded:
                    _emit(report, 'DASHBOARD_DEGRADED' if dashboard_degraded else 'DASHBOARD_OBSERVED')
                    last_dashboard_degraded = dashboard_degraded
                if is_degraded is not None and is_degraded != last_degraded:
                    _emit(report, 'RECORDER_DEGRADED' if is_degraded else 'RECORDER_RECOVERED')
                    last_degraded = is_degraded
        except (OSError, ValueError):
            is_stale = True
        if is_stale != last_stale:
            _emit(report, 'COLLECTOR_HEARTBEAT_STALE' if is_stale
                  else 'COLLECTOR_HEARTBEAT_RECOVERED')
            last_stale = is_stale
        # An independent timestamp allows the dashboard to detect a dead watchdog
        # even when no state transitions have been logged recently.
        try:
            snapshot = {'at': datetime.now(timezone.utc).isoformat(),
                        'collector_heartbeat_stale': is_stale,
                        'recorder_degraded': last_degraded if verified_heartbeat and not is_stale else None,
                        'browser_degraded': last_browser_degraded if verified_heartbeat and not is_stale else None,
                        'dashboard_degraded': last_dashboard_degraded if verified_heartbeat and not is_stale else None}
            temp = health_file.with_suffix('.tmp')
            temp.write_text(json.dumps(snapshot), encoding='utf-8')
            os.replace(temp, health_file)
        except OSError:
            # Never weaken security or terminate the browser when health reporting fails.
            pass
        if parent_alive(parent_pid) is False:
            _emit(report, 'COLLECTOR_PROCESS_EXITED')
            break
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--heartbeat', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--stop', type=Path, required=True)
    parser.add_argument('--parent', type=int, default=0)
    args = parser.parse_args()
    run(args.heartbeat, args.report, args.stop, args.parent)


if __name__ == '__main__':
    main()
