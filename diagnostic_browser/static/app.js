'use strict';
let csrf='',lastEvents=[],lastStatus=null;
const $=id=>document.getElementById(id);
function toast(msg){const el=$('toast');el.textContent=msg;el.classList.add('visible');setTimeout(()=>el.classList.remove('visible'),3500)}
async function get(url){const r=await fetch(url,{credentials:'same-origin',cache:'no-store'});if(r.status===401){location.reload();throw Error('login required')}if(!r.ok)throw Error('request failed');return r.json()}
async function post(url,body={}){const r=await fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(body)});if(!r.ok)throw Error('operation failed: '+r.status);return r.json()}
function el(tag,content,cls){const x=document.createElement(tag);if(cls)x.className=cls;x.textContent=content;return x}
function showView(view){document.querySelectorAll('.view').forEach(x=>x.classList.toggle('active',x.id===view));document.querySelectorAll('.nav').forEach(x=>x.classList.toggle('active',x.dataset.view===view));const nav=document.querySelector('.nav[data-view="'+view+'"]');$('viewTitle').textContent=nav?nav.textContent.trim():'Session Cockpit'}
function stat(id,value){$(id).textContent=String(value)}
function renderStatus(x){lastStatus=x;const count=x.recording.counts||{};
 stat('stat-events',x.events);stat('stat-incidents',x.incidents);stat('stat-targets',x.browser.monitored_pages||0);
 const state=x.recording.state;const badge=$('recording-pill');const active=Number(x.browser.monitored_pages||0);
 const watchdog=(x.watchdog||{}).state||'UNVERIFIED';
 // A living writer does not prove accurate/complete capture. Never show green
 // while watchdog or source coverage is unverifiable.
 let effective=state;
 if(x.evidence_encryption!=='SQLCIPHER')effective='ENCRYPTION NOT VERIFIED';
 else if(x.integrity!==true)effective='EVIDENCE INTEGRITY UNVERIFIED';
 else if(watchdog!=='OBSERVING')effective='WATCHDOG '+watchdog;
 else if(x.browser.state==='DEGRADED'||x.browser.state==='FAILED')effective='BROWSER DEGRADED';
 else if(state==='RECORDING'&&active===0)effective='ARMED / NO ELIGIBLE TARGET';
 else if(state==='RECORDING'&&x.browser.collector_coverage!=='FULL')effective='RECORDING / PARTIAL COVERAGE';
 badge.textContent=effective;badge.className='status-pill '+(effective==='RECORDING'?'good':'bad');
 const sys=$('system-summary');sys.replaceChildren();
 for(const [k,v] of Object.entries({'Recorder state':state,'Browser state':x.browser.state,'Collector queue':x.recording.queued,'Committed events':count.committed||0,'Queue overflows':count.queue_full||0,'Privacy rejections':count.privacy_rejected||0,'Database integrity':x.integrity?'PASS':'FAIL','At-rest encryption':x.evidence_encryption||'UNVERIFIED','Known evidence losses':x.known_losses||0,'Watchdog':(x.watchdog||{}).state||'UNVERIFIED','Capture coverage':x.browser.collector_coverage||'NOT VERIFIED'})){
  const row=el('div','');row.append(el('b',k),el('strong',v));sys.append(row);
 }
 const c=$('coverage-body');c.replaceChildren();for(const s of x.coverage){const tr=document.createElement('tr');for(const val of [s.source,s.state,s.updated])tr.append(el('td',val));c.append(tr)}
}
function renderEvents(events){lastEvents=events;stat('stat-failures',events.filter(e=>['error','critical'].includes(e.severity)).length);
 const recent=$('recent-events');recent.replaceChildren();for(const e of events.slice(-6).reverse()){
  const item=document.createElement('div');item.append(el('b',e.kind+' • '+e.severity),el('small',e.timestamp));recent.append(item);
 }if(!events.length)recent.append(el('p','No approved technical events captured yet.','muted'));
 const body=$('events-body');body.replaceChildren();const q=$('event-filter').value.toLowerCase();let n=0;
 for(const e of events.slice().reverse()){
  const full=[e.id,e.kind,e.severity,JSON.stringify(e.fields)].join(' ').toLowerCase();if(!full.includes(q))continue;n++;
  const tr=document.createElement('tr');tr.append(el('td',e.timestamp),el('td',e.kind),el('td',e.severity,'tag '+e.severity),el('td',JSON.stringify(e.fields)),el('td',e.id));body.append(tr);
 }$('timeline-count').textContent=n+' retained events shown. Display limited to most recent 200.';
}
function renderIncidents(items){const body=$('incidents-body');body.replaceChildren();for(const i of items){const tr=document.createElement('tr');for(const v of [i.id,i.at,i.trigger,i.window_start+' — '+i.window_end])tr.append(el('td',v));body.append(tr)}}
async function regression(){try{
 const [r,issues]=await Promise.all([get('/api/regression'),get('/api/known-issues')]);
 $('baseline-status').textContent=r.status==='NO_BASELINE'?'No baseline saved. Save a trusted recording to begin comparison.':r.status==='LEGACY_BASELINE_REQUIRES_RESAVE'?'Previous baseline format requires a new trusted baseline.':'Baseline: '+r.baseline_at+' · '+r.differences.length+' signatures compared';
 const rb=$('regression-body');rb.replaceChildren();for(const x of r.differences){const tr=document.createElement('tr');for(const v of [x.fingerprint,x.previous_count,x.current_count,x.classification])tr.append(el('td',v));rb.append(tr)}
 const ib=$('issues-body');ib.replaceChildren();for(const x of issues){const tr=document.createElement('tr');for(const v of [x.fingerprint,x.state,x.ticket])tr.append(el('td',v));ib.append(tr)}
 }catch(e){$('baseline-status').textContent='Regression analysis unavailable.'}}
async function refresh(){try{const [status,events,incidents]=await Promise.all([get('/api/status'),get('/api/events?limit=200'),get('/api/incidents')]);renderStatus(status);renderEvents(events);renderIncidents(incidents);if($("regression").classList.contains("active"))await regression()}catch(e){$('recording-pill').textContent='UNVERIFIED';$('recording-pill').className='status-pill bad'}}
async function mark(){try{const value=await post('/api/incidents');toast('Incident preserved: '+value.id.slice(0,8));refresh()}catch(e){toast('Unable to preserve incident')}}
async function selfTest(){try{$('selftest-result').textContent='Running checks…';const result=await post('/api/self-test');$('selftest-result').textContent=JSON.stringify(result,null,2);toast('Self-test finished; review results')}catch(e){$('selftest-result').textContent='Self-test failed';toast('Self-test failed')}}
async function exportFile(preset){try{const x=await post('/api/export',{preset});const container=$('export-result');container.replaceChildren();const msg=el('p','Verified '+x.event_count+' exported events • SHA-256: '+x.sha256);const link=el('a','Download '+x.filename);link.href='/api/export/file/'+encodeURIComponent(x.filename);link.download=x.filename;container.append(msg,link);toast('Export generated and verified')}catch(e){toast('Export failed; existing evidence preserved')}}
async function init(){try{csrf=(await get('/api/session')).csrf}catch{location.reload();return}
 document.querySelectorAll('.nav').forEach(x=>x.addEventListener('click',()=>showView(x.dataset.view)));
 document.querySelectorAll('[data-goto]').forEach(x=>x.addEventListener('click',()=>showView(x.dataset.goto)));
 $('mark').addEventListener('click',mark);$('mark2').addEventListener('click',mark);
 $('selftest').addEventListener('click',selfTest);
 $('run-ai').addEventListener('click',async()=>{const target=$('ai-result');target.textContent='Running offline inference…';try{const x=await post('/api/ai-summary');target.textContent='AI hypotheses (not verified findings):\n'+x.analysis}catch{target.textContent='Local inference unavailable or timed out; no cloud fallback.'}});
 document.querySelectorAll('button.export').forEach(x=>x.addEventListener('click',()=>exportFile(x.dataset.preset)));
 $('event-filter').addEventListener('input',()=>renderEvents(lastEvents));
 $('capture-baseline').addEventListener('click',async()=>{if(!confirm('Save the currently retained approved evidence as a trusted reference baseline?'))return;try{await post('/api/baseline');await regression();toast('Trusted baseline saved')}catch{toast('Baseline failed')}});
 $('issue-form').addEventListener('submit',async e=>{e.preventDefault();try{await post('/api/known-issues',{fingerprint:$('issue-signature').value,ticket:$('issue-ticket').value,state:$('issue-state').value});await regression();toast('Known issue saved')}catch{toast('Invalid fingerprint, ticket or state')}});
 await refresh();setInterval(refresh,4000);
}
init();
