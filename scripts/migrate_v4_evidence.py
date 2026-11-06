#!/usr/bin/env python3
"""Opt-in, copy-only migration of legacy V4 SQLite metadata to SQLCipher.

Never edits the source database, key, WAL or profile. Intended exclusively for an
authorized offline migration on the original Windows user account. Migrate a
quiescent recording, not a live V4 session, and validate before using the copy.
"""
from __future__ import annotations
import argparse
import json
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
from diagnostic_browser.store import EvidenceStore

TABLES = {
    'events': ('seq','id','at','ciphertext'),
    'incidents': ('id','at','window_start','window_end','trigger'),
    'coverage': ('source','state','updated'),
    'evidence_losses': ('id','at','reason','source','count'),
    'baselines': ('id','at','ciphertext','end_seq'),
    'known_issues': ('signature','state','ticket','updated'),
    'self_test_receipts': ('reference','event_id'),
}


def migrate(source: Path, dest: Path) -> dict:
    source = source.expanduser().resolve(strict=True)
    dest = dest.expanduser().absolute()
    if dest.exists():
        raise FileExistsError('destination already exists; existing evidence remains untouched')
    if source == dest or source in dest.parents:
        raise ValueError('destination must not be inside legacy evidence directory')
    srcdb=source/'flight_recorder.sqlite'; keyfile=source/'evidence.key'
    if not srcdb.is_file() or not keyfile.is_file():
        raise FileNotFoundError('source database/key missing; source untouched')
    with srcdb.open('rb') as file:
        if file.read(16) != b'SQLite format 3\x00':
            raise ValueError('source is not a legacy plaintext SQLite metadata database')
    if not dest.parent.is_dir():
        raise FileNotFoundError('destination parent must exist')
    reader=sqlite3.connect(srcdb.as_uri()+'?mode=ro',uri=True,isolation_level=None)
    stage=Path(tempfile.mkdtemp(prefix='db-migrate-',dir=dest.parent))
    store=None
    try:
        reader.execute('BEGIN')
        if reader.execute('PRAGMA integrity_check').fetchone()[0]!='ok':
            raise OSError('legacy evidence integrity failed')
        with (stage/'evidence.key').open('xb') as file:
            file.write(keyfile.read_bytes())
        if os.name!='nt':(stage/'evidence.key').chmod(0o600)
        store=EvidenceStore(stage)
        store.db.execute('BEGIN IMMEDIATE')
        copied={}
        tables={row[0] for row in reader.execute('SELECT name FROM sqlite_master WHERE type="table"')}
        for table,columns in TABLES.items():
            if table not in tables:
                copied[table]=0;continue
            existing={r[1] for r in reader.execute(f'PRAGMA table_info({table})')}
            present=tuple(c for c in columns if c in existing)
            if not present:
                copied[table]=0;continue
            names=','.join(present); slots=','.join('?' for _ in present)
            cursor=reader.execute(f'SELECT {names} FROM {table}')
            total=0
            for row in cursor:
                store.db.execute(f'INSERT INTO {table} ({names}) VALUES ({slots})',row)
                total+=1
            copied[table]=total
        store.db.execute('COMMIT')
        if not store.integrity() or copied['events']!=store.count():
            raise OSError('migrated evidence verification failed; source untouched')
        store.close();store=None
        # Commit before publishing. The original directory is never changed.
        stage.rename(dest)
        return {'status':'MIGRATED_COPY_READY_FOR_REVIEW','original_preserved':True,
                'destination':str(dest),'copied_rows':copied}
    except BaseException:
        if store is not None:
            try:store.db.execute('ROLLBACK')
            except Exception:pass
            store.close()
        # Keep the failed staging evidence rather than silently erasing it.
        raise
    finally:reader.close()


def main():
    p=argparse.ArgumentParser(description='Copy-only V4 legacy evidence migration')
    p.add_argument('--source',required=True,type=Path)
    p.add_argument('--destination',required=True,type=Path)
    p.add_argument('--confirm-offline-copy',action='store_true')
    args=p.parse_args()
    if not args.confirm_offline_copy:
        p.error('--confirm-offline-copy required; first stop V4 recording and protect backups')
    try:print(json.dumps(migrate(args.source,args.destination),indent=2))
    except Exception as exc:
        print(json.dumps({'status':'FAILED_SOURCE_UNCHANGED','type':type(exc).__name__}))
        return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
