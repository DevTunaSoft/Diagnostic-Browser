"""Independent process/lifecycle fault injection — no browser secrets or production data."""
from __future__ import annotations
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from diagnostic_browser import supervisor


def _args(root:Path):
    return SimpleNamespace(data_dir=str(root), url='about:blank',port=18731,
                           chrome_path=None,headless=True,synthetic_lab=True)


def test_supervisor_engine_command_keeps_dedicated_engine_role(tmp_path):
    command=supervisor.engine_command(_args(tmp_path))
    assert '--engine' in command
    assert '--data-dir' in command
    assert '--synthetic-lab' in command
    assert not any('remote-debugging-port' in value for value in command)
    assert not any('token=' in value for value in command)


def test_supervisor_bounded_restarts_with_truthful_status(tmp_path):
    launches=[]
    class Dead:
        pid=23456
        def wait(self,**kwargs):return 7
    def spawn(cmd):
        launches.append(cmd)
        return Dead()
    result=supervisor.supervise(_args(tmp_path),spawn=spawn,sleep=lambda _:None,
                                clock=lambda: 100.0)
    assert result==1
    assert len(launches)==supervisor.MAX_RESTARTS+1
    obj=json.loads((tmp_path/'supervisor.status.json').read_text())
    assert obj['state']=='ENGINE_FAILED_RESTART_LIMIT'
    assert obj['restarts']==supervisor.MAX_RESTARTS
    assert 'example' not in (tmp_path/'supervisor.status.json').read_text().lower()


def test_supervisor_success_does_not_restart(tmp_path):
    child=SimpleNamespace(pid=1234,wait=lambda :0)
    assert supervisor.supervise(_args(tmp_path),spawn=lambda cmd:child)==0
    assert json.loads((tmp_path/'supervisor.status.json').read_text())['state']=='ENGINE_STOPPED'


def test_supervisor_launch_failure_reports_without_secret(tmp_path):
    def fail(cmd):raise FileNotFoundError('this exception might contain a fake secret')
    assert supervisor.supervise(_args(tmp_path),spawn=fail)==1
    assert 'fake secret' not in (tmp_path/'supervisor.status.json').read_text()
    assert json.loads((tmp_path/'supervisor.status.json').read_text())['state']=='ENGINE_LAUNCH_FAILED'


@pytest.mark.skipif(os.name=='nt', reason='POSIX-only termination semantics; Windows requires its own acceptance test')
def test_supervisor_child_survives_launcher_process_death(tmp_path):
    """Actual OS processes, not mocks: killing launcher must not kill engine.

    The child is a harmless synthetic stand-in for the recording engine. This
    proves process-group isolation, not Windows/Chrome survival.
    """
    child_code=(
        'import os,time,pathlib; '
        f'pathlib.Path({str(tmp_path/"engine-pid")!r}).write_text(str(os.getpid())); '
        'time.sleep(25)'
    )
    sup_code=(
        'from diagnostic_browser.supervisor import spawn_engine;'
        f'spawn_engine([{sys.executable!r},"-c",{child_code!r}]);'
        'import time;time.sleep(25)'
    )
    launcher=subprocess.Popen([sys.executable,'-c',sup_code],
                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    engine_pid=None
    try:
        expiry=time.monotonic()+5
        while time.monotonic()<expiry:
            if (tmp_path/'engine-pid').exists():
                engine_pid=int((tmp_path/'engine-pid').read_text())
                break
            time.sleep(.025)
        assert engine_pid is not None
        os.kill(launcher.pid,signal.SIGKILL)
        launcher.wait(timeout=2)
        os.kill(engine_pid,0)  # Must still be alive after supervisor death
    finally:
        if launcher.poll() is None:launcher.kill();launcher.wait()
        if engine_pid is not None:
            try:os.kill(engine_pid,signal.SIGKILL)
            except ProcessLookupError:pass
