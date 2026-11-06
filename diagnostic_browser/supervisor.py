"""Resident, non-CDP process supervisor for Diagnostic Browser.

The launched engine owns the private Playwright CDP pipe and Chrome process.
The supervisor owns neither: terminating this launcher does not intentionally
close the engine or its browser. An actual engine crash may still close Chrome;
we record that loss and restart only within a strictly bounded policy.
No privileged debugging endpoint is exposed by this supervisor.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timezone

MAX_RESTARTS = 2
RESTART_WINDOW_SECONDS = 300


def atomic_status(root: Path, status: str, *, restarts: int, engine_pid: int | None = None) -> None:
    """Only fixed, non-sensitive status fields; no URLs, credentials or errors."""
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = {'at': datetime.now(timezone.utc).isoformat(), 'state': status,
            'restarts': min(max(restarts, 0), MAX_RESTARTS), 'engine_pid': engine_pid}
    pending = root / 'supervisor.status.tmp'
    with pending.open('w', encoding='utf-8') as out:
        json.dump(data, out)
        out.flush()
        os.fsync(out.fileno())
    os.replace(pending, root / 'supervisor.status.json')


def engine_command(args) -> list[str]:
    # Same bundled EXE when frozen; never require Python on an installed system.
    base = [sys.executable] if getattr(sys, 'frozen', False) else [sys.executable, '-m', 'diagnostic_browser.main']
    cmd = base + ['--engine', '--data-dir', str(args.data_dir), '--url', args.url, '--port', str(args.port)]
    if args.chrome_path:
        cmd += ['--chrome-path', args.chrome_path]
    if args.headless:
        cmd.append('--headless')
    if args.synthetic_lab:
        cmd.append('--synthetic-lab')
    return cmd


def spawn_engine(command: list[str]) -> subprocess.Popen:
    # On Windows this is a separate process group, not a child tied to browser
    # UI or Python context manager cleanup. On POSIX, setsid similarly ensures
    # process-group independence. No debug ports or privileged IPC are opened.
    kwargs = {'stdin': subprocess.DEVNULL, 'close_fds': True}
    if getattr(sys, 'frozen', False):
        # Detached or restarted engine may outlive the launching onefile
        # bootloader; give it an independent extraction lifetime.
        kwargs['env'] = {**os.environ, 'PYINSTALLER_RESET_ENVIRONMENT': '1'}
    if os.name == 'nt':
        kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs['start_new_session'] = True
    return subprocess.Popen(command, **kwargs)


def supervise(args, *, spawn=spawn_engine, sleep=time.sleep, clock=time.monotonic) -> int:
    root = Path(args.data_dir).expanduser().resolve()
    command = engine_command(args)
    restarts = []
    while True:
        (root / 'engine.stop').unlink(missing_ok=True)
        try:
            child = spawn(command)
        except OSError:
            atomic_status(root, 'ENGINE_LAUNCH_FAILED', restarts=len(restarts))
            return 1
        atomic_status(root, 'ENGINE_RUNNING', restarts=len(restarts), engine_pid=child.pid)
        try:
            result = child.wait()
        except KeyboardInterrupt:
            # Operator stops the application deliberately; request engine stop.
            # Only a live engine is signaled. Chrome cleanup remains the engine's
            # responsibility; a forced kill is NOT interpreted as clean shutdown.
            atomic_status(root, 'OPERATOR_STOP_REQUESTED', restarts=len(restarts), engine_pid=child.pid)
            stop_file = root / 'engine.stop'
            # Request the engine's own graceful cleanup. Do not send SIGTERM
            # to a process group containing an authenticated Chrome session.
            stop_file.touch(mode=0o600)
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                atomic_status(root, 'ENGINE_STOP_UNCONFIRMED', restarts=len(restarts), engine_pid=child.pid)
                return 2
            atomic_status(root, 'OPERATOR_STOPPED', restarts=len(restarts))
            return 0
        if result == 0:
            atomic_status(root, 'ENGINE_STOPPED', restarts=len(restarts))
            return 0
        now = clock()
        restarts = [value for value in restarts if now-value < RESTART_WINDOW_SECONDS]
        if len(restarts) >= MAX_RESTARTS:
            atomic_status(root, 'ENGINE_FAILED_RESTART_LIMIT', restarts=len(restarts))
            return 1
        restarts.append(now)
        atomic_status(root, 'ENGINE_FAILED_RESTARTING', restarts=len(restarts))
        sleep(min(2**len(restarts), 10))


def launch_unmonitored(args) -> subprocess.Popen:
    """Optional native desktop handoff; caller may exit without closing Chrome.

    This is an explicit detach, not a guarantee that Chrome survives death of
    its *own* CDP pipe owner. Enterprise policy must permit spawning the engine.
    """
    root = Path(args.data_dir).expanduser().resolve()
    child = spawn_engine(engine_command(args))
    atomic_status(root, 'ENGINE_LAUNCHED_UNMONITORED', restarts=0, engine_pid=child.pid)
    return child
