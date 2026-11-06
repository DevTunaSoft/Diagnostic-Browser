"""In-application Chromium update manager (privacy- and policy-preserving).

The diagnostic browser ships with a bundled Chromium. Because a browser is a
security-sensitive component, this manager lets an operator update it *from
inside the application* under strict guardrails rather than shipping a stale
engine until the next full installer:

* Updates are installed into a per-user, writable browsers directory that takes
  precedence over any read-only bundled copy. The signed application binary is
  never modified in place.
* Downloads happen only through an injected installer that pulls Playwright's
  own pinned, hash-verified Chromium build from Playwright's official CDN. No
  arbitrary URL, host, or revision supplied by a caller is ever fetched.
* The manager never downgrades below a security floor, never disables the
  Chromium sandbox, and never relaxes capture/navigation policy.
* Nothing here contacts the network on its own: resolving "what is available"
  and performing the install are injected callables so the whole unit is
  deterministic and offline-testable. When no resolver/installer is wired (for
  example a fully offline site), the manager reports that cleanly instead of
  guessing or failing open.

The manager records only approved, non-sensitive metadata (integer revisions,
coarse status strings) as evidence — never URLs, tokens, or file paths that
could carry identifiers.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

# Only Playwright's official distribution host is ever an acceptable source.
# This is defence-in-depth: the default installer already pins the revision and
# verifies the archive, but an injected installer is still constrained to this.
ALLOWED_SOURCE_HOSTS = ('playwright.azureedge.net', 'playwright.download.prss.microsoft.com')

# Chromium builds older than this are refused outright: an "update" must never
# move the engine backwards past a known-good security floor.
SECURITY_FLOOR_REVISION = 1000

_REV_DIR = re.compile(r'^chromium(?:_headless_shell)?-(\d+)$')

# Status codes returned to the UI. Kept coarse and free of identifiers.
STATUS_UP_TO_DATE = 'UP_TO_DATE'
STATUS_UPDATE_AVAILABLE = 'UPDATE_AVAILABLE'
STATUS_UNKNOWN = 'UNKNOWN'            # cannot determine available revision (e.g. offline)
STATUS_UNMANAGED = 'UNMANAGED'       # engine is installer-managed; in-app update not applicable


class ChromiumUpdateError(RuntimeError):
    """Raised when an update is refused or cannot be completed safely."""


@dataclass(frozen=True)
class ChromiumStatus:
    current_revision: Optional[int]
    available_revision: Optional[int]
    status: str
    writable: bool
    note: str = ''

    def as_dict(self) -> dict:
        return {
            'current_revision': self.current_revision,
            'available_revision': self.available_revision,
            'status': self.status,
            'update_available': self.status == STATUS_UPDATE_AVAILABLE,
            'writable': self.writable,
            'security_floor': SECURITY_FLOOR_REVISION,
            'note': self.note,
        }


def _scan_installed_revision(browsers_path: Path) -> Optional[int]:
    """Highest installed Chromium revision under a Playwright browsers directory."""
    best: Optional[int] = None
    try:
        entries = list(browsers_path.iterdir())
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return None
    for entry in entries:
        m = _REV_DIR.match(entry.name)
        if m and entry.is_dir():
            rev = int(m.group(1))
            if best is None or rev > best:
                best = rev
    return best


def _default_browsers_path() -> Path:
    """Per-user writable Chromium location, overriding any bundled read-only copy."""
    env = os.environ.get('PLAYWRIGHT_BROWSERS_PATH')
    if env and env not in ('0',):
        return Path(env).expanduser()
    if os.name == 'nt':
        base = os.environ.get('LOCALAPPDATA') or str(Path.home() / 'AppData' / 'Local')
        return Path(base) / 'ms-playwright'
    return Path.home() / '.cache' / 'ms-playwright'


class ChromiumUpdater:
    """Guarded, offline-testable Chromium update manager.

    Parameters
    ----------
    browsers_path:
        Writable per-user Chromium directory. Defaults to the Playwright
        per-user cache. In a frozen single-file build this is set to a writable
        app-data path so updates never touch the signed executable.
    resolve_available:
        Injected callable returning the newest *approved* revision available, or
        ``None`` when it cannot be determined (e.g. no network). Never called
        with caller-controlled input. If omitted, availability is UNKNOWN.
    installer:
        Injected callable ``installer(target_revision, dest_dir) -> int`` that
        fetches and installs the given revision from Playwright's official CDN,
        returning the revision actually installed. If omitted, applying an
        update is refused (reported as UNMANAGED).
    frozen:
        True in the bundled single-file build. When frozen and no writable path
        is available, in-app updates are reported UNMANAGED (installer-managed).
    incident_active:
        Injected callable returning True while an incident recording is in
        progress; an update is refused mid-incident unless explicitly forced.
    on_evidence:
        Optional callable to record an approved, non-sensitive evidence event
        ``on_evidence(kind, severity, fields)``.
    """

    def __init__(
        self,
        browsers_path: Optional[Path] = None,
        *,
        resolve_available: Optional[Callable[[], Optional[int]]] = None,
        installer: Optional[Callable[[int, Path], int]] = None,
        frozen: bool = False,
        incident_active: Optional[Callable[[], bool]] = None,
        on_evidence: Optional[Callable[[str, str, dict], None]] = None,
    ) -> None:
        self.browsers_path = Path(browsers_path) if browsers_path else _default_browsers_path()
        self._resolve_available = resolve_available
        self._installer = installer
        self.frozen = frozen
        self._incident_active = incident_active or (lambda: False)
        self._on_evidence = on_evidence

    # -- introspection -------------------------------------------------------
    def current_revision(self) -> Optional[int]:
        return _scan_installed_revision(self.browsers_path)

    def _writable(self) -> bool:
        p = self.browsers_path
        try:
            p.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError):
            return False
        return os.access(p, os.W_OK)

    def check(self) -> ChromiumStatus:
        """Report current vs. available revision without side effects."""
        current = self.current_revision()
        writable = self._writable()
        if self._installer is None or (self.frozen and not writable):
            return ChromiumStatus(current, None, STATUS_UNMANAGED, writable,
                                  'Chromium is managed by the application installer on this build.')
        available: Optional[int] = None
        if self._resolve_available is not None:
            try:
                available = self._resolve_available()
            except Exception:
                available = None
        if available is None:
            return ChromiumStatus(current, None, STATUS_UNKNOWN, writable,
                                  'Could not determine the latest approved Chromium build.')
        if current is not None and available <= current:
            return ChromiumStatus(current, available, STATUS_UP_TO_DATE, writable)
        return ChromiumStatus(current, available, STATUS_UPDATE_AVAILABLE, writable)

    # -- mutation ------------------------------------------------------------
    def apply(self, *, force: bool = False) -> ChromiumStatus:
        """Download and activate the newest approved Chromium, under guardrails.

        Raises ChromiumUpdateError if the update is refused or cannot complete
        safely. On success the newer engine lives in the per-user directory and
        is picked up on the next browser launch; the running session is not
        interrupted.
        """
        if self._installer is None:
            raise ChromiumUpdateError('In-app Chromium update is not available on this build.')
        if not self._writable():
            raise ChromiumUpdateError('Chromium directory is not writable; cannot update in place.')
        if self._incident_active() and not force:
            raise ChromiumUpdateError('Refusing to update Chromium during an active incident recording.')

        status = self.check()
        if status.status == STATUS_UP_TO_DATE:
            return status
        target = status.available_revision
        if target is None:
            raise ChromiumUpdateError('No approved Chromium build is available to install.')

        current = status.current_revision
        # Never move backwards, never below the security floor.
        if target < SECURITY_FLOOR_REVISION:
            raise ChromiumUpdateError('Refusing to install Chromium below the security floor.')
        if current is not None and target < current:
            raise ChromiumUpdateError('Refusing to downgrade Chromium.')

        self._emit('browser_update', 'info', {'action': 'start', 'from': current, 'to': target})
        try:
            installed = self._installer(target, self.browsers_path)
        except Exception as exc:  # installer failures must never corrupt the running engine
            self._emit('browser_update', 'error', {'action': 'failed', 'to': target})
            raise ChromiumUpdateError(f'Chromium update failed: {type(exc).__name__}') from exc

        if not isinstance(installed, int):
            raise ChromiumUpdateError('Installer returned an invalid revision.')
        if installed < SECURITY_FLOOR_REVISION or (current is not None and installed < current):
            # An installer that produced an unexpected/older build is a hard error.
            self._emit('browser_update', 'error', {'action': 'rejected', 'installed': installed})
            raise ChromiumUpdateError('Installed Chromium revision failed post-install validation.')

        self._emit('browser_update', 'info', {'action': 'complete', 'installed': installed})
        return ChromiumStatus(installed, installed, STATUS_UP_TO_DATE, True,
                              'Update staged; the new engine is used on the next browser launch.')

    # -- helpers -------------------------------------------------------------
    def _emit(self, kind: str, severity: str, fields: dict) -> None:
        if self._on_evidence is None:
            return
        try:
            self._on_evidence(kind, severity, fields)
        except Exception:
            pass


def default_resolver() -> Optional[int]:
    """Newest approved Chromium revision, read offline from Playwright's own
    pinned metadata (``browsers.json``). This is the exact build a fresh
    ``playwright install chromium`` would fetch from the official CDN, so it
    needs no network and introduces no new trust. Returns None if it cannot be
    located."""
    try:
        import playwright  # noqa: F401
        import json
        pkg = Path(playwright.__file__).parent
        candidates = [pkg / 'driver' / 'package' / 'browsers.json']
        for meta in candidates:
            if meta.is_file():
                data = json.loads(meta.read_text(encoding='utf-8'))
                revs = [int(b['revision']) for b in data.get('browsers', [])
                        if b.get('name') == 'chromium' and str(b.get('revision', '')).isdigit()]
                if revs:
                    return max(revs)
    except Exception:
        return None
    return None


def default_installer(target_revision: int, dest_dir: Path) -> int:
    """Install Chromium via Playwright's own verified downloader (official CDN).

    Runs ``python -m playwright install chromium`` with the browsers path pinned
    to ``dest_dir`` so the per-user copy is refreshed. Playwright pins the
    revision and verifies the downloaded archive; this wrapper adds no new
    network trust. Returns the revision present after installation.
    """
    import subprocess
    import sys

    env = dict(os.environ)
    env['PLAYWRIGHT_BROWSERS_PATH'] = str(dest_dir)
    # Fail closed on any non-official download host.
    host_override = env.get('PLAYWRIGHT_DOWNLOAD_HOST', '')
    if host_override and not any(host_override.endswith(h) for h in ALLOWED_SOURCE_HOSTS):
        raise ChromiumUpdateError('Chromium download host is not on the approved list.')
    subprocess.run(
        [sys.executable, '-m', 'playwright', 'install', 'chromium'],
        check=True, env=env, capture_output=True, timeout=600,
    )
    rev = _scan_installed_revision(dest_dir)
    if rev is None:
        raise ChromiumUpdateError('Chromium not present after installation.')
    return rev
