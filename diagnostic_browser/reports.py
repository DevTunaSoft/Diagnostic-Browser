"""Verified privacy-safe offline engineering support exports."""
from __future__ import annotations
import csv
import hashlib
import html
import io
import json
import os
import tempfile
import zipfile
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from .store import EvidenceStore
from .policy import normalize

REPORT_JS = '''document.addEventListener('DOMContentLoaded',()=>{
 const filter=document.getElementById('filter');
 const count=document.getElementById('visible');
 const rows=[...document.querySelectorAll('#events tbody tr')];
 function update(){const q=filter.value.toLowerCase();let n=0;for(const r of rows){const ok=r.textContent.toLowerCase().includes(q);r.hidden=!ok;if(ok)n++}count.textContent=String(n)}
 filter.addEventListener('input',update);update();
});'''

def jsonl(data):return ''.join(json.dumps(x,sort_keys=True,separators=(',',':'))+'\n' for x in data)

def build_html(events, incidents, title, known_losses=0, *, total_events=None, error_count=None):
    # All fields are finite, normalized enums and integers; HTML still escapes them.
    def esc(v):return html.escape(str(v),quote=True)
    # Avoid building an unbounded browser DOM for very large recordings.
    # The machine-readable JSONL/CSV still includes every approved event.
    shown = events[-5000:]
    rows=[]
    for e in shown:
        fields=', '.join(f'{k}={v}' for k,v in sorted(e['fields'].items()))
        rows.append('<tr><td>'+esc(e['timestamp'])+'</td><td>'+esc(e['kind'])+'</td><td>'+esc(e['severity'])+'</td><td>'+esc(fields)+'</td><td><code>'+esc(e['id'])+'</code></td></tr>')
    source="""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'; style-src 'unsafe-inline'; script-src 'sha256-__HASH__'"><title>Diagnostic Browser — Offline Evidence</title><style>
body{font-family:system-ui,Segoe UI,sans-serif;background:#0b1525;color:#e6eef7;margin:0;padding:32px}header{max-width:1300px;margin:auto}h1{letter-spacing:-.04em;font-size:30px;margin-bottom:8px}.hint{color:#a4b8cc}.pill{display:inline-block;border:1px solid #385471;border-radius:40px;padding:5px 12px;color:#c2e2ff;font-size:12px}.panel{background:#111f34;border:1px solid #254363;border-radius:14px;padding:22px;margin:20px auto;max-width:1300px}.metrics{display:flex;gap:18px}.metric{flex:1;padding:14px;background:#1b2d45;border-radius:8px}.metric strong{font-size:26px;display:block}input{background:#0a1829;color:#fff;border:1px solid #627a94;padding:12px;border-radius:8px;min-width:310px}table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:12px;text-align:left;border-bottom:1px solid #2b435e;vertical-align:top;overflow-wrap:anywhere}th{color:#b1c9e4}code{font-size:11px;color:#8fd3d8}tr[hidden]{display:none}footer{max-width:1300px;margin:20px auto;color:#a4b8cc;font-size:12px}
</style></head><body><header><span class="pill">OFFLINE • SANITIZED • NO EXTERNAL CONNECTIONS</span><h1>Diagnostic Browser</h1><div class="hint">__TITLE__</div></header><section class="panel"><h2>Recording summary</h2><div class="metrics"><div class="metric"><strong>__COUNT__</strong>approved events</div><div class="metric"><strong>__INCIDENTS__</strong>incident markers</div><div class="metric"><strong>__ERRORS__</strong>error or critical events</div><div class="metric"><strong>__LOSSES__</strong>known recording gaps</div></div><p class="hint">Only policy-approved fields are exported. HTML displays the latest 5,000 records; JSONL/CSV contain all approved records. Monitoring gaps and excluded sources limit completeness.</p></section><section class="panel"><h2>Technical event timeline</h2><label for="filter">Filter evidence </label><input id="filter" type="search" placeholder="Search type, severity or ID" autocomplete="off"><span class="hint"> <span id="visible">__VIEW_COUNT__</span> visible</span><div style="overflow:auto"><table id="events"><thead><tr><th>UTC timestamp</th><th>Category</th><th>Severity</th><th>Approved details</th><th>Event ID</th></tr></thead><tbody>__ROWS__</tbody></table></div></section><footer>Diagnostic Browser • Evidence snapshot • Designed to exclude patient data, authentication credentials, and request bodies. No automated privacy check guarantees zero disclosure. Full approved event records are supplied in JSONL.</footer><script>__JS__</script></body></html>"""
    digest=hashlib.sha256(REPORT_JS.encode()).digest()
    import base64
    script_hash=base64.b64encode(digest).decode()
    return (source.replace('__HASH__',script_hash).replace('__TITLE__',esc(title)).replace('__COUNT__',str(total_events if total_events is not None else len(events)))
       .replace('__VIEW_COUNT__',str(len(shown))).replace('__INCIDENTS__',str(len(incidents))).replace('__ERRORS__',str(error_count if error_count is not None else sum(e['severity'] in ('error','critical') for e in events))).replace('__LOSSES__',str(known_losses))
       .replace('__ROWS__',''.join(rows)).replace('__JS__',REPORT_JS)).encode()

def build_pdf(events,incidents,title,known_losses=0, *, total_events=None, error_count=None, category_counts=None):
    buf=io.BytesIO()
    doc=SimpleDocTemplate(buf,pagesize=letter,topMargin=36,bottomMargin=36,leftMargin=45,rightMargin=45)
    st=getSampleStyleSheet()
    st.add(ParagraphStyle(name='DBTitle',parent=st['Heading1'],fontSize=22,leading=26,textColor=colors.HexColor('#13345b'),spaceAfter=10))
    st.add(ParagraphStyle(name='DBNote',parent=st['Normal'],textColor=colors.HexColor('#4c6178'),leading=15,spaceAfter=14))
    st.add(ParagraphStyle(name='DBSmall',parent=st['Normal'],fontSize=8,leading=11))
    story=[Paragraph('DIAGNOSTIC BROWSER',st['DBTitle']),Paragraph(html.escape(title),st['Heading2']),
           Paragraph('Engineering evidence summary | Approved technical metadata only',st['DBNote'])]
    count=category_counts if category_counts is not None else Counter(e['kind'] for e in events)
    data=[['METRIC','VALUE'],['Approved events',str(total_events if total_events is not None else len(events))],['Preserved incidents',str(len(incidents))],
          ['Errors and critical',str(error_count if error_count is not None else sum(e['severity'] in ('error','critical') for e in events))],
          ['Known event or correlation losses',str(known_losses)],
          ['Collection coverage','See coverage.json in archive']]
    table=Table(data,colWidths=[255,255],hAlign='LEFT')
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#13345b')),('TEXTCOLOR',(0,0),(-1,0),colors.white),
          ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.whitesmoke,colors.white]),('GRID',(0,0),(-1,-1),.35,colors.HexColor('#d6e0ec')),
          ('TOPPADDING',(0,0),(-1,-1),9),('BOTTOMPADDING',(0,0),(-1,-1),9)]))
    story.extend([table,Spacer(1,20),Paragraph('Observed event categories',st['Heading2'])])
    for kind,num in sorted(count.items()):story.append(Paragraph(f'{html.escape(kind)} — {num}',st['Normal']))
    story.extend([Spacer(1,15),Paragraph('Recent evidence (maximum 50 records)',st['Heading2'])])
    for event in events[-50:]:
        desc=f"{event['timestamp']} | {event['kind']} | {event['severity']} | {event['id']}"
        story.append(Paragraph(html.escape(desc),st['DBSmall']))
        story.append(Spacer(1,5))
    story.extend([Spacer(1,12),Paragraph('Evidence interpretation notice',st['Heading2']),
       Paragraph('Recorded observations do not establish the underlying server-side cause. Coverage gaps and exclusions are listed in the machine-readable archive. No unrestricted browser traces, screenshots, cookies, tokens or application bodies are included.',st['DBNote'])])
    doc.build(story)
    return buf.getvalue()

def build_csv(events):
    output=io.StringIO(newline='')
    writer=csv.writer(output,lineterminator='\n')
    writer.writerow(['event_id','session','timestamp_utc','kind','severity','fields_json'])
    for e in events:
        # Excel formula injection avoided by fixed string fields / JSON-quoted payloads.
        writer.writerow([e['id'],e['session'],e['timestamp'],e['kind'],e['severity'],json.dumps(e['fields'],sort_keys=True)])
    return output.getvalue().encode('utf-8')

def export_bundle(store: EvidenceStore, destination: Path, preset='engineering', health: dict | None=None) -> dict:
    """Export ALL approved rows with bounded memory and verified per-file hashes.

    The caller starts a consistent SQLite read transaction before invoking us.
    Only the last 5,000 events are retained in RAM for HTML/PDF presentation.
    JSONL and CSV exports contain the complete retained approved timeline.
    """
    if preset not in {'engineering','internal','system-health'}:
        raise ValueError('invalid export preset')
    if not store.integrity():
        raise OSError('database integrity failed')
    incidents=store.incidents()
    cover=store.coverage()
    losses=store.losses()
    known_loss_count=sum(x['count'] for x in losses)
    title=('IT Internal Diagnostic Archive' if preset=='internal' else
           'System Health Report' if preset=='system-health' else 'Engineering Support Report')
    destination=Path(destination).expanduser().resolve()
    destination.parent.mkdir(parents=True,exist_ok=True)
    fd,temp=tempfile.mkstemp(prefix='db-export-',suffix='.zip',dir=destination.parent)
    os.close(fd)
    count=0; errors=0; categories=Counter()
    recent=deque(maxlen=5000)
    hashes={}
    try:
        with zipfile.ZipFile(temp,'w',compression=zipfile.ZIP_DEFLATED,allowZip64=True) as archive:
            # The output is generated directly from validated event rows. No
            # unrestricted Chrome events are ever serialized to either stream.
            jhash=hashlib.sha256();chash=hashlib.sha256()
            with archive.open('03_Full_Event_Timeline.jsonl','w',force_zip64=True) as json_file:
                for event in store.iter_events():
                    if (preset == 'system-health' and event['kind'] not in
                       {'health','collection_gap','coverage','storage_error','self_test'}):
                        continue
                    normalize(event['kind'],event['severity'],event['fields'])
                    count+=1;categories[event['kind']]+=1
                    errors+=int(event['severity'] in ('error','critical'))
                    recent.append(event)
                    line=(json.dumps(event,sort_keys=True,separators=(',',':'))+'\n').encode('utf-8')
                    json_file.write(line);jhash.update(line)
            with archive.open('04_Full_Event_Timeline.csv','w',force_zip64=True) as csv_file:
                head=b'event_id,session,timestamp_utc,kind,severity,fields_json\r\n'
                csv_file.write(head);chash.update(head)
                csv_count=0
                for event in store.iter_events():
                    if (preset == 'system-health' and event['kind'] not in
                       {'health','collection_gap','coverage','storage_error','self_test'}):
                        continue
                    csv_count+=1
                    row=io.StringIO(newline='')
                    csv.writer(row,lineterminator='\n').writerow(
                        [event['id'],event['session'],event['timestamp'],
                         event['kind'],event['severity'],
                         json.dumps(event['fields'],sort_keys=True)])
                    data=row.getvalue().encode('utf-8')
                    csv_file.write(data);chash.update(data)
                if csv_count != count:
                    raise OSError('CSV event count mismatch')
            hashes['03_Full_Event_Timeline.jsonl']=jhash.hexdigest()
            hashes['04_Full_Event_Timeline.csv']=chash.hexdigest()
            recent=list(recent)
            contents={
               '01_Engineering_Report.pdf':build_pdf(
                   recent,incidents,title,known_loss_count,
                   total_events=count,error_count=errors,category_counts=categories),
               '02_Offline_Interactive_Report.html':build_html(
                   recent,incidents,title,known_loss_count,
                   total_events=count,error_count=errors),
               '05_Incidents.json':json.dumps(incidents,indent=2).encode(),
               '06_Coverage.json':json.dumps(cover,indent=2).encode(),
               '06A_Evidence_Loss_Ledger.json':json.dumps(losses,indent=2).encode(),
               '06B_Regression_Comparison.json':json.dumps(store.compare_baseline(),indent=2).encode(),
               '06C_Known_Issues.json':json.dumps(store.known_issues(),indent=2).encode(),
               '06D_System_Health.json':json.dumps(health or {'state':'UNAVAILABLE'},indent=2).encode(),
               '07_Privacy_Policy.json':json.dumps({
                   'allowlist_only':True,'sensitive_bodies_collected':False,
                   'secret_scanning_note': 'Canary tests and policy validation cannot guarantee zero arbitrary secrets.',
                   'approved_record_count':count,'preset':preset},indent=2).encode(),
            }
            for name,content in contents.items():
                archive.writestr(name,content)
                hashes[name]=hashlib.sha256(content).hexdigest()
            archive.writestr('08_SHA256_Manifest.json',json.dumps({
                'generated_utc':datetime.now(timezone.utc).isoformat(),
                'schema':3,'files_sha256':hashes,'event_count':count,
                'known_loss_count':known_loss_count,
                'viewer_limit':5000,
                'original_evidence_unchanged':True,
            },indent=2).encode())
        with zipfile.ZipFile(temp,'r') as z:
            if z.testzip() is not None:raise OSError('invalid ZIP checksum')
            manifest=json.loads(z.read('08_SHA256_Manifest.json'))
            for name,expected in manifest['files_sha256'].items():
                digest=hashlib.sha256()
                with z.open(name) as contents:
                    for chunk in iter(lambda:contents.read(1024*1024),b''):
                        digest.update(chunk)
                if digest.hexdigest()!=expected:
                    raise OSError('manifest verification failed')
            with z.open('03_Full_Event_Timeline.jsonl') as timeline:
                if sum(1 for _ in timeline)!=count:
                    raise OSError('event count mismatch')
        os.replace(temp,destination)
    finally:
        if os.path.exists(temp):os.unlink(temp)
    digest=hashlib.sha256()
    with destination.open('rb') as finished:
        for chunk in iter(lambda:finished.read(1024*1024),b''):
            digest.update(chunk)
    return dict(path=str(destination),event_count=count,sha256=digest.hexdigest())
