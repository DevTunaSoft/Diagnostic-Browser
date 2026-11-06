#!/usr/bin/env python3
"""Mandatory on-Windows encrypted-at-rest verification; no network requests."""
from __future__ import annotations
import json
import sqlite3
import sys
import tempfile
from pathlib import Path


def verify():
    from sqlcipher3 import dbapi2 as sqlcipher
    from diagnostic_browser.store import EvidenceStore
    with tempfile.TemporaryDirectory(prefix='diagnostic-browser-cipher-') as tmp:
        directory = Path(tmp)
        store = EvidenceStore(directory)
        try:
            assert store.encryption_backend == 'SQLCIPHER'
            canary = 'SYNTHETIC_PRIVATE_MARKER_DO_NOT_PERSIST_IN_PLAINTEXT'
            item = store.add('health','info',{'target':'collector','code':'READY'})
            assert store.integrity()
            cipher_row = store.db.execute('PRAGMA cipher_status').fetchone()
            # SQLCipher returns pragma values as text ('1'), not int; coerce before comparing.
            assert cipher_row and int(cipher_row[0]) == 1
            # A committed row exists before close. Don't open with ordinary SQLite.
            store.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        finally:
            store.close()
        file = directory/'flight_recorder.sqlite'
        assert file.is_file()
        header = file.open('rb').read(16)
        assert header != b'SQLite format 3\x00', 'unencrypted database found'
        with sqlite3.connect(file) as plain:
            try:
                plain.execute('SELECT name FROM sqlite_master').fetchall()
            except sqlite3.DatabaseError:
                pass
            else:
                raise AssertionError('ordinary SQLite opened encrypted evidence without a key')
        reopened = EvidenceStore(directory,read_only=True)
        try:
            assert reopened.encryption_backend == 'SQLCIPHER'
            assert reopened.integrity()
            assert reopened.count() == 1
            assert reopened.recent_events(1)[0]['id'] == item['id']
        finally:
            reopened.close()
    return {'status':'PASS','whole_file_encryption':'VERIFIED','sqlcipher_reopen':'PASS',
            'windows_runtime':sys.platform=='win32','network_used':False}

if __name__=='__main__':
    try:
        result=verify()
    except Exception as exc:
        print(json.dumps({'status':'FAIL','error_type':type(exc).__name__,
                          'note':'No database secret or raw exception text is printed'}))
        sys.exit(1)
    else:
        print(json.dumps(result,indent=2))
        if not result['windows_runtime']:
            sys.exit(2)
