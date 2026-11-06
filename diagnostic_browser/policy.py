"""Fail-closed privacy policy. This module MUST remain independent of the browser SDK."""
from __future__ import annotations
import re
import os
import ipaddress
from urllib.parse import urlsplit, unquote
from dataclasses import dataclass
from typing import Any

VALID_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
VALID_SEVERITIES = frozenset({"info", "warning", "error", "critical"})
VALID_KINDS = frozenset({
    "http_error", "http_activity", "network_failure", "js_exception", "console_warning",
    "websocket_open", "websocket_closed", "websocket_error", "transport_polling",
    "browser_crash", "collection_gap", "coverage", "health", "manual_marker",
    "storage_error", "self_test", "release_change", "security_issue",
})
DIAGNOSTIC_CODES = frozenset({"CONSOLE_WARNING", "BROWSER_LOG_WARNING", "SYNTHETIC_EVENT_ACCEPTED", "BROWSER_LAUNCH_FAILED", "READY", "PRIVACY_GATE_ACTIVE", "RECORDER_HEALTH_OK", "NAVIGATION_FAILED", "BROWSER_POLICY_BLOCKED", "BROWSER_REQUEST_BLOCKED", "DASHBOARD_RESTART_REQUIRED"})
ERROR_CLASSES = frozenset({"Error", "TypeError", "ReferenceError", "SyntaxError", "RangeError", "URIError", "EvalError", "AggregateError", "DOMException"})
NET_ERRORS = frozenset({
    "ERR_INTERNET_DISCONNECTED", "ERR_CONNECTION_RESET", "ERR_CONNECTION_REFUSED",
    "ERR_CONNECTION_TIMED_OUT", "ERR_TIMED_OUT", "ERR_NAME_NOT_RESOLVED",
    "ERR_CERT_AUTHORITY_INVALID", "ERR_CERT_DATE_INVALID", "ERR_ABORTED",
    "ERR_BLOCKED_BY_CLIENT", "ERR_FAILED", "ERR_EMPTY_RESPONSE", "ERR_HTTP2_PROTOCOL_ERROR",
    "ERR_NETWORK_CHANGED", "ERR_TUNNEL_CONNECTION_FAILED", "ERR_PROXY_CONNECTION_FAILED",
    "ERR_CONNECTION_CLOSED", "ERR_SSL_PROTOCOL_ERROR", "ERR_BLOCKED_BY_ADMINISTRATOR",
})

# Only fixed output labels. We do NOT retain arbitrary URLs, paths or query parameters.
ROUTES = [
    (re.compile(r"^/socket\.io(?:/|$)", re.I), "socket.io"),
    (re.compile(r"^/cpdom(?:/|$)", re.I), "cpdom"),
    (re.compile(r"^/api(?:/|$)", re.I), "api"),
    (re.compile(r"^/scripts(?:/|$)|^/js(?:/|$)", re.I), "javascript_asset"),
    (re.compile(r"^/css(?:/|$)|^/styles(?:/|$)", re.I), "stylesheet_asset"),
    (re.compile(r"^/assets(?:/|$)|^/static(?:/|$)", re.I), "static_asset"),
]

def _valid_host(host: str) -> bool:
    if not host or len(host) > 253 or host.endswith('.') or '*' in host:
        return False
    if host == 'localhost' or host.endswith('.localhost'):
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    labels = host.split('.')
    return len(labels) >= 2 and all(
        0 < len(label) <= 63 and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', label)
        for label in labels
    )

@dataclass(frozen=True)
class Scope:
    test_local: bool = False
    # Explicitly configured hosts only. Empty configuration disables production capture.
    allowed_hosts: tuple[str, ...] = ()

    @staticmethod
    def configured() -> "Scope":
        raw = os.environ.get("DIAGNOSTIC_BROWSER_ALLOWED_HOSTS", "")
        hosts = tuple(x.strip().lower() for x in raw.split(",") if x.strip())
        if len(hosts) > 32 or any(not _valid_host(x) for x in hosts):
            raise ValueError("Invalid capture host configuration")
        return Scope(allowed_hosts=hosts)

    def allowed(self, url: str) -> bool:
        if not isinstance(url, str) or len(url) > 16384: return False
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower().rstrip(".")
            if parts.username or parts.password: return False
            if self.test_local and parts.scheme in ("http", "ws") and host == "127.0.0.1": return True
            if parts.port not in (None, 443): return False
            if parts.scheme not in ("https", "wss"): return False
            if host not in self.allowed_hosts:
                return False
            # An authentication domain may share a parent domain with the
            # application. Host authorization alone is NOT permission to
            # record sign-in, OAuth/SAML redirects, or credential exchanges.
            labels = host.split('.')
            auth_labels = {'login','logon','auth','sso','idp','identity','okta','accounts','signin'}
            if any(label in auth_labels for label in labels[:-2]):
                return False
            # Decode a bounded number of layers before checking authentication routes.
            # Encoded separators and dot segments must not make sign-in URLs appear safe.
            path = parts.path.replace('\\', '/')
            for _ in range(4):
                decoded = unquote(path, errors='replace').replace('\\', '/')
                if decoded == path:
                    break
                path = decoded
            if '%' in path or '\x00' in path:
                return False
            segments = [segment.lower() for segment in path.split('/') if segment and segment != '.']
            if '..' in segments:
                return False
            auth_prefixes = {'login','logon','logout','signin','signout','oauth',
                             'oauth2','authorize','sso','saml','openid','oidc','auth'}
            if segments and segments[0] in auth_prefixes:
                return False
            if len(segments) >= 2 and segments[:2] == ['connect', 'authorize']:
                return False
            return True
        except (ValueError, TypeError):
            return False

    def category(self, url: str) -> str | None:
        if not self.allowed(url): return None
        try:
            path = urlsplit(url).path
        except ValueError:
            return "unclassified"
        for pattern, label in ROUTES:
            if pattern.match(path): return label
        return "unclassified"

# One shared coverage identity contract for host, IPC receiver, and store.
# Mismatched regexes previously let the host queue source IDs which the
# evidence store could never commit, stalling the entire transport bridge.
COVERAGE_SOURCE_PATTERN = (
    r'(?:page:[0-9]{1,20}|nested-targets:page:[0-9]{1,20}|'
    r'(?:worker|iframe|shared_worker|service_worker|collector):[0-9a-f]{32})'
)

SAFE_FIELDS = frozenset({
    "method", "status", "route", "resource", "error_class", "error_code",
    "line", "column", "socket_state", "reason", "count", "target", "detail_code",
    "cache", "service_worker", "protocol", "sequence", "coverage", "code", "incident_id",
    "request_ref", "redirect_chain",
})
ENUM_FIELDS = {
    "resource": frozenset({"Document", "XHR", "Fetch", "Script", "Stylesheet", "Image", "WebSocket", "Other", "Preflight", "EventSource", "Manifest", "Font", "Ping"}),
    "socket_state": frozenset({"created", "handshake", "closed", "frame_error", "polling"}),
    "target": frozenset({"page", "frame", "worker", "service_worker", "browser", "collector", "storage", "watchdog", "dashboard"}),
    "reason": frozenset({"manual", "automatic", "disconnected", "queue_full", "write_failed", "unavailable", "not_attached", "target_closed", "privacy_rejected", "synthetic", "crash", "start", "stop", "recovered", "failed", "unknown"}),
    "coverage": frozenset({"ACTIVE", "EXCLUDED", "UNSUPPORTED", "UNATTACHED", "DISCONNECTED", "FAILING", "RECOVERING"}),
    "cache": frozenset({"yes", "no", "unknown"}),
    "service_worker": frozenset({"yes", "no", "unknown"}),
    "protocol": frozenset({"h2", "http/1.1", "h3", "unknown"}),
}

class UnsafeEvent(ValueError): pass

def network_code(text: Any) -> str:
    # A network error string can include an arbitrary address; only match known code tokens.
    if not isinstance(text, str): return "ERR_OTHER"
    # Limit regex work on untrusted browser strings while retaining common Chromium prefixes.
    text = text[:4096]
    match = re.search(r"\b(ERR_[A-Z0-9_]+)\b", text)
    if match and match.group(1) in NET_ERRORS: return match.group(1)
    return "ERR_OTHER"

def normalize(kind: str, severity: str, fields: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    if not isinstance(kind, str) or not isinstance(severity, str) or kind not in VALID_KINDS or severity not in VALID_SEVERITIES or not isinstance(fields, dict):
        raise UnsafeEvent("unrecognized event type, severity, or fields")
    clean: dict[str, Any] = {}
    # Unknown keys are rejected, not silently serialized.
    if any(not isinstance(key, str) or key not in SAFE_FIELDS for key in fields): raise UnsafeEvent("unapproved field")
    for key, value in fields.items():
        if key in ENUM_FIELDS:
            if not isinstance(value, str) or value not in ENUM_FIELDS[key]: raise UnsafeEvent("unapproved enumeration")
        elif key == "method":
            if not isinstance(value, str) or value not in VALID_METHODS: raise UnsafeEvent("invalid HTTP method")
        elif key == "status":
            if not isinstance(value, int) or isinstance(value, bool) or not 100 <= value <= 599: raise UnsafeEvent("invalid HTTP status")
        elif key == "route":
            if not isinstance(value, str) or value not in {name for _, name in ROUTES} | {"unclassified"}: raise UnsafeEvent("unapproved route")
        elif key == "error_class":
            if not isinstance(value, str) or value not in ERROR_CLASSES | {"UnknownError"}: raise UnsafeEvent("unapproved error class")
        elif key == "error_code":
            if not isinstance(value, str) or value not in NET_ERRORS | {"ERR_OTHER"}: raise UnsafeEvent("unapproved network code")
        elif key in {"count", "line", "column", "sequence"}:
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 10_000_000: raise UnsafeEvent("invalid numeric value")
        elif key in {"incident_id", "request_ref", "redirect_chain"}:
            if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32}", value): raise UnsafeEvent("invalid incident id")
        elif key in {"code", "detail_code"}:
            if not isinstance(value, str) or value not in DIAGNOSTIC_CODES: raise UnsafeEvent("invalid diagnostic code")
        else:
            raise UnsafeEvent("unhandled allowlisted field")
        clean[key] = value
    return kind, severity, clean
