"""Encrypted, fail-closed SQLCipher evidence database with DPAPI-wrapped per-profile key.

Plain SQLite is permitted solely for isolated automated tests. Never use a
plaintext database for actual browsing, nor silently migrate or downgrade one.
"""
from __future__ import annotations
import os
import re
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .policy import normalize, COVERAGE_SOURCE_PATTERN


def utcnow() -> datetime: return datetime.now(timezone.utc)


def protect_key_win(key: bytes) -> bytes:
    """DPAPI current-user key wrapping, never calls out to any network service."""
    import ctypes
    from ctypes import wintypes
    class BLOB(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]
    raw = ctypes.create_string_buffer(key)
    inp = BLOB(len(key), ctypes.cast(raw, ctypes.POINTER(ctypes.c_ubyte)))
    out = BLOB()
    crypt = ctypes.windll.crypt32
    if not crypt.CryptProtectData(ctypes.byref(inp), None, None, None, None, 0x1, ctypes.byref(out)):
        raise OSError("DPAPI encryption failed")
    try: return ctypes.string_at(out.data, out.size)
    finally:
        free = ctypes.windll.kernel32.LocalFree
        free.argtypes = [ctypes.c_void_p]
        free.restype = ctypes.c_void_p
        free(ctypes.cast(out.data, ctypes.c_void_p))


def unprotect_key_win(data: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes
    class BLOB(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]
    raw = ctypes.create_string_buffer(data)
    inp = BLOB(len(data), ctypes.cast(raw, ctypes.POINTER(ctypes.c_ubyte)))
    out = BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(inp), None, None, None, None, 0x1, ctypes.byref(out)):
        raise OSError("DPAPI key unavailable; prior evidence must not be overwritten")
    try: return ctypes.string_at(out.data, out.size)
    finally:
        free = ctypes.windll.kernel32.LocalFree
        free.argtypes = [ctypes.c_void_p]
        free.restype = ctypes.c_void_p
        free(ctypes.cast(out.data, ctypes.c_void_p))


def load_key(root: Path) -> bytes:
    key_path = root / "evidence.key"
    if key_path.exists():
        data = key_path.read_bytes()
        key = unprotect_key_win(data) if os.name == 'nt' else data
        if len(key) != 32: raise OSError("invalid evidence key; refusing to recreate")
        return key
    # Never silently rotate away historical evidence when the wrapped key is lost.
    if any((root / name).exists() for name in
           ('flight_recorder.sqlite', 'flight_recorder.sqlite-wal',
            'flight_recorder.sqlite-shm')):
        raise OSError('evidence key missing; refusing to overwrite historic evidence')
    key = os.urandom(32)
    data = protect_key_win(key) if os.name == 'nt' else key
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(key_path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data);f.flush();os.fsync(f.fileno())
    except BaseException:
        key_path.unlink(missing_ok=True)
        raise
    return key

def _open_evidence_db(path: Path, key: bytes, *, read_only: bool = False,
                      allow_test_plaintext: bool = False):
    """Require proven SQLCipher before any production evidence can be opened.

    The test fallback is explicitly gated on pytest's active test context; a
    production launcher cannot activate it through a configuration toggle.
    """
    test_context = (os.environ.get('DIAGNOSTIC_BROWSER_TEST_PLAINTEXT') == '1'
                    and bool(os.environ.get('PYTEST_CURRENT_TEST')))
    if allow_test_plaintext and not test_context:
        raise RuntimeError('plaintext evidence backend permitted only during automated tests')
    if allow_test_plaintext:
        connection = sqlite3.connect(
            path.as_uri() + '?mode=ro' if read_only else path,
            uri=read_only, isolation_level=None, check_same_thread=False)
        return connection, 'TEST_PLAINTEXT'
    try:
        from sqlcipher3 import dbapi2 as sqlcipher
    except ImportError as exc:
        raise RuntimeError('SQLCipher is required for encrypted evidence storage; refusing startup') from exc
    connection = sqlcipher.connect(
        path.as_uri() + '?mode=ro' if read_only else str(path),
        uri=read_only, isolation_level=None, check_same_thread=False)
    try:
        # Raw 256-bit key rather than a textual passphrase; no credentials logged.
        connection.execute("PRAGMA key = \"x'" + key.hex() + "'\"")
        version = connection.execute('PRAGMA cipher_version').fetchone()
        if not version or not version[0]:
            raise RuntimeError('loaded SQLite library does not support SQLCipher encryption')
        connection.execute('PRAGMA temp_store=MEMORY')
        # Detect wrong key, existing unencrypted legacy database or damaged data
        # before attempting schema creation. Never overwrite or auto-downgrade.
        connection.execute('SELECT count(*) FROM sqlite_master').fetchone()
        if not read_only:
            connection.execute('PRAGMA secure_delete=ON')
        return connection, 'SQLCIPHER'
    except BaseException:
        connection.close()
        raise


class EvidenceStore:
    def __init__(self, root: Path, read_only: bool = False, *, allow_test_plaintext: bool = False):
        self.root = Path(root).expanduser().resolve()
        if not read_only:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        database_path = self.root / "flight_recorder.sqlite"
        if read_only and (not database_path.is_file() or not (self.root / "evidence.key").is_file()):
            raise FileNotFoundError("read-only evidence source is missing")
        # A missing native cipher must not create an orphaned key or a
        # misleading, seemingly initialized evidence profile.
        if not allow_test_plaintext:
            try:
                from sqlcipher3 import dbapi2 as _verified_sqlcipher  # noqa: F401
            except ImportError as exc:
                raise RuntimeError('SQLCipher missing; no evidence profile initialized') from exc
            # This application uses DPAPI to protect the *database key* on disk.
            # A non-Windows production run would otherwise save that key raw.
            if os.name != 'nt':
                raise RuntimeError('Production evidence storage requires Windows DPAPI')
        key = load_key(self.root)
        self._aes = AESGCM(key)
        self.db, self.encryption_backend = _open_evidence_db(
            database_path, key, read_only=read_only,
            allow_test_plaintext=allow_test_plaintext)
        if read_only:
            self.session_id = uuid4().hex
            return
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            at TEXT NOT NULL,
            ciphertext BLOB NOT NULL
          );
          CREATE INDEX IF NOT EXISTS idx_events_at ON events(at);
          CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY, at TEXT NOT NULL, window_start TEXT NOT NULL,
            window_end TEXT NOT NULL, trigger TEXT NOT NULL
          );
          CREATE TABLE IF NOT EXISTS coverage (
            source TEXT PRIMARY KEY, state TEXT NOT NULL, updated TEXT NOT NULL
          );
          CREATE TABLE IF NOT EXISTS evidence_losses (
            id TEXT PRIMARY KEY, at TEXT NOT NULL, reason TEXT NOT NULL,
            source TEXT NOT NULL, count INTEGER NOT NULL
          );
          CREATE TABLE IF NOT EXISTS baselines (
            id TEXT PRIMARY KEY, at TEXT NOT NULL, ciphertext BLOB NOT NULL,
            end_seq INTEGER
          );
          CREATE TABLE IF NOT EXISTS known_issues (
            signature TEXT PRIMARY KEY, state TEXT NOT NULL, ticket TEXT NOT NULL, updated TEXT NOT NULL
          );
          CREATE TABLE IF NOT EXISTS self_test_receipts (
            reference TEXT PRIMARY KEY, event_id TEXT NOT NULL UNIQUE
          );
        ''')
        # Migrate old V4.1 databases without discarding existing encrypted baselines.
        # Historical baselines without a stored sequence cannot be compared reliably.
        baseline_columns = {row[1] for row in self.db.execute('PRAGMA table_info(baselines)')}
        if 'end_seq' not in baseline_columns:
            self.db.execute('ALTER TABLE baselines ADD COLUMN end_seq INTEGER')
        self.session_id = uuid4().hex

    def add(self, kind: str, severity: str, fields: dict,
            observed_at: datetime | None = None, event_id: str | None = None) -> dict:
        kind, severity, fields = normalize(kind, severity, fields)
        if event_id is not None:
            if (not isinstance(event_id, str) or len(event_id) != 32
                    or any(c not in "0123456789abcdef" for c in event_id)):
                raise ValueError("invalid event id")
        if observed_at is not None:
            if not isinstance(observed_at, datetime) or observed_at.tzinfo is None or observed_at.utcoffset() is None:
                raise ValueError('observed_at must be a timezone-aware datetime')
            if not (-1 <= (utcnow()-observed_at).total_seconds() <= 86400):
                raise ValueError('observed_at outside accepted recorder window')
        at = (observed_at or utcnow()).astimezone(timezone.utc).isoformat(timespec='milliseconds')
        if event_id is not None:
            existing = self.db.execute('SELECT ciphertext FROM events WHERE id=?', (event_id,)).fetchone()
            if existing:
                old_payload = existing[0]
                old_event = json.loads(self._aes.decrypt(
                    old_payload[:12], old_payload[12:], event_id.encode()))
                # Retries are safe only if they describe the same observation;
                # a reused event ID with a different value is a collision.
                if (old_event['timestamp'] != at or old_event['kind'] != kind
                        or old_event['severity'] != severity or old_event['fields'] != fields):
                    raise ValueError('conflicting duplicate event reference')
                return {'id': event_id, 'duplicate': True}
        eid = event_id or uuid4().hex
        event = dict(id=eid, session=self.session_id, timestamp=at, kind=kind, severity=severity, fields=fields, schema=1)
        # Authenticated associated data binds ciphertext to its DB row id.
        nonce = os.urandom(12)
        payload = nonce + self._aes.encrypt(nonce, json.dumps(event, separators=(',', ':')).encode(), eid.encode())
        if kind == 'self_test' and 'request_ref' in fields:
            # Commit both records atomically: the exact probe is indexed using
            # a random reference, without exposing event payload fields.
            self.db.execute('SAVEPOINT self_test_receipt')
            try:
                self.db.execute("INSERT INTO events(id,at,ciphertext) VALUES (?,?,?)", (eid, at, payload))
                self.db.execute("INSERT INTO self_test_receipts(reference,event_id) VALUES (?,?)",
                                (fields['request_ref'], eid))
                self.db.execute('RELEASE SAVEPOINT self_test_receipt')
            except BaseException:
                self.db.execute('ROLLBACK TO SAVEPOINT self_test_receipt')
                self.db.execute('RELEASE SAVEPOINT self_test_receipt')
                raise
        else:
            self.db.execute("INSERT INTO events(id,at,ciphertext) VALUES (?,?,?)", (eid, at, payload))
        return event

    def verify_self_test(self, reference: str) -> bool:
        if not isinstance(reference, str) or len(reference) != 32 or any(c not in '0123456789abcdef' for c in reference):
            return False
        row = self.db.execute("SELECT e.id,e.ciphertext FROM self_test_receipts s JOIN events e ON e.id=s.event_id WHERE s.reference=?", (reference,)).fetchone()
        if row is None:
            return False
        eid, payload = row
        event = json.loads(self._aes.decrypt(payload[:12],payload[12:],eid.encode()))
        normalize(event['kind'], event['severity'], event['fields'])
        return event['kind'] == 'self_test' and event['fields'].get('request_ref') == reference

    def recent_events(self, limit: int = 200) -> list[dict]:
        """Bounded dashboard lookup; avoids decrypting the whole flight history every poll.

        Exports and baselines continue to use the complete events() method.
        """
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ValueError('recent event limit must be between 1 and 1000')
        rows = self.db.execute(
            'SELECT id,ciphertext FROM events ORDER BY seq DESC LIMIT ?', (limit,)
        ).fetchall()
        output = []
        for eid, payload in reversed(rows):
            obj = json.loads(self._aes.decrypt(payload[:12], payload[12:], eid.encode()))
            normalize(obj['kind'], obj['severity'], obj['fields'])
            output.append(obj)
        return output

    def iter_events(self):
        """Yield approved evidence one row at a time from the caller's snapshot."""
        cursor = self.db.execute('SELECT id,ciphertext FROM events ORDER BY seq ASC')
        for eid, payload in cursor:
            obj = json.loads(self._aes.decrypt(payload[:12], payload[12:], eid.encode()))
            normalize(obj['kind'], obj['severity'], obj['fields'])
            yield obj

    def events(self, since: str | None = None, until: str | None = None) -> list[dict]:
        query = "SELECT id,ciphertext FROM events WHERE 1=1"
        args = []
        if since: query += " AND at>=?";args.append(since)
        if until: query += " AND at<=?";args.append(until)
        query += " ORDER BY seq ASC"
        result = []
        for eid, payload in self.db.execute(query, args):
            obj = json.loads(self._aes.decrypt(payload[:12], payload[12:], eid.encode()))
            normalize(obj['kind'], obj['severity'], obj['fields'])
            result.append(obj)
        return result

    def mark(self, trigger: str = 'manual', minutes_before: int = 30, minutes_after: int = 10,
             observed_at: datetime | None = None) -> dict:
        if trigger not in {"manual", "automatic"}: raise ValueError("invalid incident trigger")
        if (not isinstance(minutes_before, int) or isinstance(minutes_before, bool) or
            not isinstance(minutes_after, int) or isinstance(minutes_after, bool) or
            not 0 <= minutes_before <= 1440 or not 0 <= minutes_after <= 1440):
            raise ValueError("invalid incident recording window")
        now = observed_at if observed_at is not None else utcnow()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ValueError('incident timestamp must be timezone aware')
        if not (-1 <= (utcnow() - now).total_seconds() <= 86400):
            raise ValueError('incident timestamp outside accepted window')
        now = now.astimezone(timezone.utc)
        item = dict(id=uuid4().hex, at=now.isoformat(timespec='milliseconds'),
                    window_start=(now - timedelta(minutes=minutes_before)).isoformat(timespec='milliseconds'),
                    window_end=(now + timedelta(minutes=minutes_after)).isoformat(timespec='milliseconds'), trigger=trigger)
        # Both the incident and its event marker must commit together. A partially
        # created incident would otherwise appear preserved despite a failed write.
        self.db.execute('SAVEPOINT incident_marker')
        try:
            self.db.execute("INSERT INTO incidents VALUES (:id,:at,:window_start,:window_end,:trigger)", item)
            self.add('manual_marker', 'warning' if trigger == 'automatic' else 'info', {'reason': trigger, 'incident_id': item['id']}, observed_at=now)
            self.db.execute('RELEASE SAVEPOINT incident_marker')
        except BaseException:
            self.db.execute('ROLLBACK TO SAVEPOINT incident_marker')
            self.db.execute('RELEASE SAVEPOINT incident_marker')
            raise
        return item

    def incidents(self) -> list[dict]:
        return [dict(zip(('id','at','window_start','window_end','trigger'), r)) for r in self.db.execute("SELECT id,at,window_start,window_end,trigger FROM incidents ORDER BY at DESC")]

    def set_coverage(self, source: str, state: str) -> None:
        if not isinstance(source,str) or not re.fullmatch(
            COVERAGE_SOURCE_PATTERN, source):
            raise ValueError('invalid coverage source')
        if state not in {'ACTIVE','EXCLUDED','UNSUPPORTED','UNATTACHED','DISCONNECTED','FAILING','RECOVERING'}: raise ValueError('invalid coverage state')
        self.db.execute("INSERT INTO coverage VALUES (?,?,?) ON CONFLICT(source) DO UPDATE SET state=excluded.state,updated=excluded.updated", (source,state,utcnow().isoformat()))

    def coverage(self) -> list[dict]:
        return [dict(source=r[0],state=r[1],updated=r[2]) for r in self.db.execute("SELECT source,state,updated FROM coverage ORDER BY source")]

    def prune(self, retention_minutes: int = 30, max_events: int = 200000) -> int:
        cutoff = (utcnow()-timedelta(minutes=retention_minutes)).isoformat()
        # An incident's full window is preserved, even after ordinary rolling retention expiry.
        deleted = self.db.execute('''DELETE FROM events WHERE at < ? AND NOT EXISTS
           (SELECT 1 FROM incidents WHERE events.at BETWEEN incidents.window_start AND incidents.window_end)''', (cutoff,)).rowcount
        self.db.execute('DELETE FROM self_test_receipts WHERE event_id NOT IN (SELECT id FROM events)')
        if self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0] > max_events:
            raise OSError("evidence event quota exceeded; preserved incidents not deleted")
        return deleted

    def record_loss(self, reason: str, source: str = 'collector', count: int = 1, loss_id: str | None = None) -> None:
        """Record an explicit known loss without storing raw diagnostic input."""
        if reason not in {'QUEUE_FULL', 'WRITE_FAILED', 'REQUEST_EVICTED',
                          'ATTACHMENT_GAP', 'POLICY_EXCLUDED'}:
            raise ValueError('unknown evidence-loss classification')
        if source not in {'collector', 'browser', 'request_ledger'}:
            raise ValueError('unknown evidence-loss source')
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise ValueError('invalid loss count')
        if loss_id is not None and (not isinstance(loss_id, str) or len(loss_id) != 32
                                    or any(c not in '0123456789abcdef' for c in loss_id)):
            raise ValueError('invalid evidence loss reference')
        self.db.execute('INSERT OR IGNORE INTO evidence_losses VALUES(?,?,?,?,?)',
                        (loss_id or uuid4().hex, utcnow().isoformat(timespec='milliseconds'),
                         reason, source, count))

    def losses(self) -> list[dict]:
        return [dict(id=row[0], at=row[1], reason=row[2], source=row[3], count=row[4])
                for row in self.db.execute('SELECT id,at,reason,source,count FROM evidence_losses ORDER BY at')]

    def integrity(self) -> bool:
        if self.encryption_backend == 'SQLCIPHER':
            cipher_result = self.db.execute('PRAGMA cipher_integrity_check').fetchall()
            if cipher_result:
                return False
        return self.db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'

    def save_baseline(self) -> dict:
        from .analysis import count_signatures
        now=utcnow().isoformat(timespec='milliseconds')
        eid=uuid4().hex
        counts=count_signatures(self.events())
        nonce=os.urandom(12)
        ciphertext=nonce+self._aes.encrypt(nonce,json.dumps(counts,sort_keys=True).encode(),eid.encode())
        last_seq = self.db.execute('SELECT COALESCE(MAX(seq),0) FROM events').fetchone()[0]
        self.db.execute("INSERT INTO baselines(id,at,ciphertext,end_seq) VALUES (?,?,?,?)",
                        (eid,now,ciphertext,last_seq))
        return dict(id=eid,at=now,signature_count=len(counts))

    def baseline(self):
        row=self.db.execute("SELECT id,at,ciphertext,end_seq FROM baselines ORDER BY at DESC LIMIT 1").fetchone()
        if row is None:return None
        eid,at,data,end_seq=row
        counts=json.loads(self._aes.decrypt(data[:12],data[12:],eid.encode()))
        return dict(id=eid,at=at,counts=counts,end_seq=end_seq)

    def compare_baseline(self) -> dict:
        from .analysis import compare,count_signatures
        old=self.baseline()
        if not old:return dict(status='NO_BASELINE',differences=[])
        if old['end_seq'] is None:
            return dict(status='LEGACY_BASELINE_REQUIRES_RESAVE',differences=[])
        # Compare the saved baseline to subsequent events only. Including baseline
        # events again creates spurious 'PERSISTENT' results and hides resolutions.
        results = []
        for event_id, payload in self.db.execute(
                'SELECT id,ciphertext FROM events WHERE seq>? ORDER BY seq',
                (old['end_seq'],)):
            obj = json.loads(self._aes.decrypt(payload[:12],payload[12:],event_id.encode()))
            normalize(obj['kind'],obj['severity'],obj['fields'])
            results.append(obj)
        return dict(status='COMPARED',baseline_id=old['id'],baseline_at=old['at'],
                    baseline_event_count=sum(old['counts'].values()),
                    comparison_event_count=sum(count_signatures(results).values()),
                    differences=compare(old['counts'],count_signatures(results)))

    def upsert_issue(self, fingerprint:str, ticket:str, state:str):
        from .analysis import ISSUE_STATES,validate_ticket
        if not isinstance(fingerprint,str) or len(fingerprint)!=64 or any(c not in '0123456789abcdef' for c in fingerprint):
            raise ValueError('invalid signature')
        if state not in ISSUE_STATES:raise ValueError('invalid issue state')
        ticket=validate_ticket(ticket)
        self.db.execute("INSERT INTO known_issues VALUES (?,?,?,?) ON CONFLICT(signature) DO UPDATE SET state=excluded.state,ticket=excluded.ticket,updated=excluded.updated",(fingerprint,state,ticket,utcnow().isoformat()))

    def known_issues(self):
        return [dict(fingerprint=r[0],state=r[1],ticket=r[2],updated=r[3]) for r in self.db.execute("SELECT signature,state,ticket,updated FROM known_issues ORDER BY updated DESC")]

    def count(self) -> int:
        return self.db.execute("SELECT count(*) FROM events").fetchone()[0]

    def close(self):
        self.db.close()
