"""Read-only diagnostics for enterprise Chromium URL access policies.

Policy inspection is informational, not authoritative: cloud, profile, group
policy and machine settings can override individual files. Only the browser's
actual navigation result is evidence that an attempted navigation was blocked.
No modifying, suppressing, or bypassing administrator policy is supported.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable


# These directories are managed by the operating environment, not by the app.
LINUX_POLICY_DIRS = (
    Path('/etc/chromium/policies/managed'),
    Path('/etc/opt/chrome/policies/managed'),
    Path('/etc/opt/edge/policies/managed'),
)


def _safe_policy_arrays(blob: Any) -> tuple[bool, bool]:
    if not isinstance(blob, dict):
        return False, False
    blocked = blob.get('URLBlocklist')
    allowed = blob.get('URLAllowlist')
    wildcard = isinstance(blocked, list) and any(v == '*' for v in blocked)
    has_exceptions = isinstance(allowed, list) and any(isinstance(v, str) and bool(v) for v in allowed)
    return wildcard, has_exceptions


def inspect_policy_files(paths: Iterable[Path]) -> dict[str, object]:
    """Only reports status and counts; does not expose policy URL entries."""
    count = 0
    wildcard = False
    exceptions = False
    unreadable = 0
    for path in paths:
        try:
            if not path.is_file() or path.suffix.lower() != '.json':
                continue
            if path.stat().st_size > 1_000_000:
                unreadable += 1
                continue
            value = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, UnicodeError, ValueError):
            unreadable += 1
            continue
        count += 1
        w, a = _safe_policy_arrays(value)
        wildcard |= w
        exceptions |= a
    return {
        'source': 'local_managed_policy_files',
        'examined_files': count,
        'unreadable_files': unreadable,
        'wildcard_block_configured': wildcard,
        'allowlist_entries_configured': exceptions,
        'interpretation': (
            'WILDCARD_BLOCK_WITH_POSSIBLE_EXCEPTIONS' if wildcard and exceptions else
            'WILDCARD_BLOCK_CONFIGURED' if wildcard else
            'NO_LOCAL_WILDCARD_BLOCK_FOUND'
        ),
        'actual_navigation_verified': False,
        'administrator_override_attempted': False,
    }


def inspect_local_policy() -> dict[str, object]:
    # Windows policies may be sourced from Group Policy, MDM and Chrome cloud
    # management; a file-based inspection there is intentionally not presented
    # as authoritative. chrome://policy is the preferred Windows source.
    if os.name == 'nt':
        return {
            'source': 'windows_managed_browser',
            'interpretation': 'REVIEW_CHROME_POLICY_AND_ENTERPRISE_CONFIGURATION',
            'actual_navigation_verified': False,
            'administrator_override_attempted': False,
        }
    return inspect_policy_files(
        path for directory in LINUX_POLICY_DIRS if directory.is_dir()
        for path in directory.glob('*.json')
    )


def classify_navigation_exception(error: BaseException) -> str:
    """Classify errors without persisting raw browser strings or target URLs."""
    # Browser runtime errors can contain URLs and sensitive fragments. They
    # are examined only transiently and never saved or returned.
    message = str(error).upper()
    if 'ERR_BLOCKED_BY_ADMINISTRATOR' in message:
        return 'BROWSER_POLICY_BLOCKED'
    if 'ERR_BLOCKED_BY_CLIENT' in message:
        return 'BROWSER_REQUEST_BLOCKED'
    return 'NAVIGATION_FAILED'
