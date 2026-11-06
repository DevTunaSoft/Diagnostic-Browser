"""Single-instance lock for a diagnostic browser profile (Windows/POSIX)."""
from __future__ import annotations
import contextlib
import os
from pathlib import Path

@contextlib.contextmanager
def lock_profile(root: Path):
    """OS-managed nonblocking lock; always released on process exit/crash.

    The lock file contains no credentials, URIs, patient data or process dump.
    """
    root=Path(root).expanduser().resolve()
    root.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd=os.open(root/'diagnostic_browser.instance.lock',os.O_RDWR|os.O_CREAT,0o600)
    acquired=False
    try:
        if os.name=='nt':
            import msvcrt
            os.lseek(fd,0,os.SEEK_SET)
            if os.fstat(fd).st_size == 0:os.write(fd,b'0')
            os.lseek(fd,0,os.SEEK_SET)
            try:msvcrt.locking(fd,msvcrt.LK_NBLCK,1)
            except OSError as exc:raise RuntimeError('diagnostic profile already in use') from exc
        else:
            import fcntl
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError as exc:raise RuntimeError('diagnostic profile already in use') from exc
        acquired=True
        yield
    finally:
        if acquired:
            if os.name=='nt':
                import msvcrt
                os.lseek(fd,0,os.SEEK_SET)
                msvcrt.locking(fd,msvcrt.LK_UNLCK,1)
            else:
                import fcntl
                fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)
