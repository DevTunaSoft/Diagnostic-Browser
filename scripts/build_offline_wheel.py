#!/usr/bin/env python3
"""Reproducible pure-Python wheel from local sources; no PyPI/network required.

Native SQLCipher, Chrome and Windows runtime dependencies are not bundled.
"""
from __future__ import annotations
import base64, hashlib, csv, io, os, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
NAME='diagnostic_browser'
VERSION='5.0.0rc4'
DIST=f'{NAME}-{VERSION}.dist-info'


def b64_digest(payload):
    return base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode().rstrip('=')


def build():
    output=ROOT/'dist'/f'{NAME}-{VERSION}-py3-none-any.whl'
    output.parent.mkdir(exist_ok=True)
    package=ROOT/NAME
    entries={}
    for file in sorted(package.rglob('*')):
        if not file.is_file() or '__pycache__' in file.parts or file.suffix in {'.pyc','.pyo'}:
            continue
        entries[file.relative_to(ROOT).as_posix()]=file.read_bytes()
    entries[DIST+'/WHEEL']=(
        'Wheel-Version: 1.0\nGenerator: DiagnosticBrowser-offline-wheel\n'
        'Root-Is-Purelib: true\nTag: py3-none-any\n').encode()
    entries[DIST+'/METADATA']=(
        f'Metadata-Version: 2.1\nName: diagnostic-browser\nVersion: {VERSION}\n'
        'Summary: IT-only, privacy-first Chromium diagnostic recorder - development release candidate\n'
        'Requires-Python: >=3.11\nRequires-Dist: playwright>=1.50,<2\n'
        'Requires-Dist: sqlcipher3>=0.6.2,<1\n'
        'Requires-Dist: cryptography>=43,<48\n'
        'Requires-Dist: fastapi>=0.115,<1\n'
        'Requires-Dist: uvicorn>=0.30,<1\n'
        'Requires-Dist: reportlab>=4,<5\n').encode()
    entries[DIST+'/entry_points.txt']=(
        '[console_scripts]\ndiagnostic-browser = diagnostic_browser.main:main\n').encode()
    record=io.StringIO(newline='')
    csv_writer=csv.writer(record,lineterminator='\n')
    for name,content in sorted(entries.items()):
        csv_writer.writerow([name,'sha256='+b64_digest(content),len(content)])
    csv_writer.writerow([DIST+'/RECORD','',''])
    entries[DIST+'/RECORD']=record.getvalue().encode()
    with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for name,content in sorted(entries.items()):
            info=zipfile.ZipInfo(name, date_time=(2026,10,31,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o644 << 16
            z.writestr(info,content)
    with zipfile.ZipFile(output) as z:
        assert z.testzip() is None
        assert len(z.namelist())==len(entries)
    print(output)
if __name__=='__main__':build()
