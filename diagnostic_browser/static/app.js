'use strict';
let csrf='',lastEvents=[],lastStatus=null;
const $=id=>document.getElementById(id);
function toast(msg){const el=$('toast');el.textContent=msg;el.classList.add('visible');setTimeout(()=>el.classList.remove('visible'),3500)}
async function get(url){const r=await fetch(url,{credentials:'same-origin',cache:'no-store'});if(r.status===401){location.reload();throw Error('login required')}if(!r.ok)throw Error('request failed');return r.json()}
async function post(url,body={}){const r=await fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(body)});if(!r.ok)throw Error('operation failed: '+r.status);return r.json()}
function el(tag,content,cls){const x=document.createElement(tag);if(cls)x.className=cls;x.textContent=content;return x}
function showView(view){document.querySelectorAll('.view').forEach(x=>x.classList.toggle('active',x.id===view));document.querySelectorAll('.nav').forEach(x=>x.classList.toggle('active',x.dataset.view===view));const nav=document.querySelector('.nav[data-view="'+view+'"]');$('viewTitle').textContent=nav?nav.textContent.trim():'Session Cockpit';if(view==='updates')chromiumRefresh();if(view==='browser')loadTarget()}
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
 renderChrome(x,effective,watchdog);
 const sys=$('system-summary');sys.replaceChildren();
 for(const [k,v] of Object.entries({'Recorder state':state,'Browser state':x.browser.state,'Collector queue':x.recording.queued,'Committed events':count.committed||0,'Queue overflows':count.queue_full||0,'Privacy rejections':count.privacy_rejected||0,'Database integrity':x.integrity?'PASS':'FAIL','At-rest encryption':x.evidence_encryption||'UNVERIFIED','Known evidence losses':x.known_losses||0,'Watchdog':(x.watchdog||{}).state||'UNVERIFIED','Capture coverage':x.browser.collector_coverage||'NOT VERIFIED'})){
  const row=el('div','');row.append(el('b',k),el('strong',v));sys.append(row);
 }
 const c=$('coverage-body');c.replaceChildren();for(const s of x.coverage){const tr=document.createElement('tr');for(const val of [s.source,s.state,s.updated])tr.append(el('td',val));c.append(tr)}
}
function setChip(id,sub,cls){const c=$(id);if(!c)return;$(id+'-sub').textContent=sub;c.className='chip'+(cls?' '+cls:'')}
function diagRow(label,value,cls){const li=document.createElement('li');
 const l=document.createElement('div');l.className='d-label';const ic=el('span',cls==='bad'?'✕':cls==='warn'?'!':'✓','d-ic'+(cls?' '+cls:''));l.append(ic,el('span',label));
 li.append(l,el('span',value,'d-val'));return li}
function renderChrome(x,effective,watchdog){
 const rec=x.recording||{},br=x.browser||{},count=rec.counts||{};
 const encOk=x.evidence_encryption==='SQLCIPHER',intOk=x.integrity===true,wdOk=watchdog==='OBSERVING';
 const recording=rec.state==='RECORDING';
 // topbar chips
 setChip('chip-rec',recording?'Recording':(rec.state||'Idle'),recording?'':'warn');
 setChip('chip-diag',br.state==='ARMED'?'Active':(br.state||'—'),(br.state==='DEGRADED'||br.state==='FAILED')?'bad':'');
 setChip('chip-heal',wdOk?'Armed':(watchdog||'Unverified'),wdOk?'':'warn');
 // health card
 const hc=$('health-card'),head=hc.querySelector('.health-head');
 const allOk=encOk&&intOk&&wdOk&&!(br.state==='DEGRADED'||br.state==='FAILED');
 head.className='health-head'+(allOk?'':' bad');
 $('health-title').textContent=allOk?'All Systems Healthy':'Attention Needed';
 $('hc-browser').textContent=br.state||'—';
 $('hc-collector').textContent=(br.bridge_connected||rec.state==='RECORDING')?'Connected':'Idle';
 $('hc-db').textContent=encOk?'Encrypted 🔒':(x.evidence_encryption||'Unverified');
 $('hc-watchdog').textContent=wdOk?'Active':(watchdog||'Unverified');
 // right rail — live diagnostics
 const dl=$('diag-list');dl.replaceChildren();
 dl.append(
  diagRow('Recorder',rec.state||'—',recording?'':'warn'),
  diagRow('Browser',br.state||'—',(br.state==='DEGRADED'||br.state==='FAILED')?'bad':''),
  diagRow('Monitored targets',String(br.monitored_pages||0),(br.monitored_pages||0)?'':'warn'),
  diagRow('Collector queue',String(rec.queued||0),''),
  diagRow('Encryption',encOk?'SQLCipher':(x.evidence_encryption||'—'),encOk?'':'bad'),
  diagRow('Integrity',intOk?'Verified':'Unverified',intOk?'':'bad'),
  diagRow('Watchdog',watchdog||'—',wdOk?'':'warn'),
  diagRow('Privacy rejections',String(count.privacy_rejected||0),''));
 // right rail — flight recorder
 const rk=$('rail-recorder');rk.replaceChildren();
 for(const [k,v] of Object.entries({'State':rec.state||'—','Committed events':count.committed||0,'Queued':rec.queued||0,'Overflows':count.queue_full||0,'Known losses':x.known_losses||0})){
  const row=el('div','');row.append(el('b',k),el('strong',String(v)));rk.append(row);}
 const rb=$('rail-rec-badge');rb.textContent=recording?'● REC':'IDLE';rb.className='rec-badge'+(recording?'':' off');
 // right rail — alerts
 const al=$('rail-alerts');al.replaceChildren();
 const issues=[];
 if(!encOk)issues.push('At-rest encryption unverified');
 if(!intOk)issues.push('Evidence integrity unverified');
 if(!wdOk)issues.push('Watchdog '+(watchdog||'unverified').toLowerCase());
 if(br.state==='DEGRADED'||br.state==='FAILED')issues.push('Browser '+br.state.toLowerCase());
 if(!issues.length){const ok=document.createElement('div');ok.className='ok';ok.append(el('span','✓'),el('span','No active issues'));al.append(ok);}
 else for(const m of issues){al.append(el('p',m,'al'));}
 // browser viewport + address bar
 if($('vp-browser')){$('vp-browser').textContent=br.state||'—';$('vp-targets').textContent=String(br.monitored_pages||0);
  $('vp-coverage').textContent=br.collector_coverage||'NOT VERIFIED';$('vp-recorder').textContent=rec.state||'—';}
 if(currentTarget&&$('tab-title'))$('tab-title').textContent=currentTarget.host||'Diagnostic session';
}
let currentTarget=null;
async function loadTarget(){try{const r=await get('/api/target');currentTarget=r.target||null;
 if(currentTarget){if($('target-input')&&!document.activeElement.isSameNode($('target-input')))$('target-input').value=currentTarget.url;
  if($('tab-title'))$('tab-title').textContent=currentTarget.host;
  if($('vp-title'))$('vp-title').textContent='Diagnosing '+currentTarget.host;
  if($('vp-sub'))$('vp-sub').textContent='The diagnostic browser is scoped to this host. Browse it in the diagnostic window; sanitized evidence appears in the flight recorder and the live log below.';}
 }catch(e){}}
async function diagnoseTarget(ev){if(ev)ev.preventDefault();
 const inp=$('target-input'),btn=$('target-go'),res=$('target-result');
 let url=(inp.value||'').trim();if(!url)return;
 if(!/^https?:\/\//i.test(url))url='https://'+url;
 res.style.display='block';res.textContent='Launching the diagnostic browser for '+url+' … this can take a few seconds.';btn.disabled=true;inp.disabled=true;
 try{const r=await post('/api/target',{url});currentTarget=r.target;
  res.textContent='Now diagnosing '+r.target.host+'. Browse it in the diagnostic window; events will appear below and in the Flight Recorder.';
  toast('Diagnostic target set: '+r.target.host);await loadTarget();await refresh();
 }catch(e){res.textContent='Could not set target: '+(e.message||'rejected').replace('operation failed: ','');toast('Target not set')}
 finally{btn.disabled=false;inp.disabled=false}
}
const LOG_MAP={network:['http_activity','http_error','network_failure'],console:['console','console_message'],cpdom:['cpdom'],websocket:['websocket'],socketio:['socketio','socket_io'],iframe:['iframe'],worker:['worker']};
let logFilter='all';
function renderLog(events){const body=$('log-body');if(!body)return;body.replaceChildren();
 let rows=events.slice().reverse();
 if(logFilter==='errors')rows=rows.filter(e=>['error','critical'].includes(e.severity));
 else if(logFilter!=='all'){const kinds=LOG_MAP[logFilter]||[];rows=rows.filter(e=>kinds.includes(e.kind))}
 if(!rows.length){const tr=document.createElement('tr');const td=el('td','No approved events for this channel yet.','empty');td.colSpan=4;tr.append(td);body.append(tr);return}
 for(const e of rows.slice(0,120)){const tr=document.createElement('tr');
  tr.append(el('td',e.timestamp),el('td',e.kind),el('td',e.severity,'tag '+e.severity),el('td',JSON.stringify(e.fields)));body.append(tr)}
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
 renderLog(events);
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
const CHROMIUM_LABEL={UP_TO_DATE:'UP TO DATE',UPDATE_AVAILABLE:'UPDATE AVAILABLE',UNKNOWN:'UNKNOWN',UNMANAGED:'INSTALLER-MANAGED'};
async function chromiumRefresh(){const badge=$('chromium-badge'),box=$('chromium-status'),btn=$('chromium-update-btn');
 badge.textContent='CHECKING';
 try{const s=await get('/api/chromium/status');
  badge.textContent=CHROMIUM_LABEL[s.status]||s.status;
  box.replaceChildren();
  for(const [k,v] of Object.entries({'Installed revision':s.current_revision??'Unknown','Latest approved revision':s.available_revision??'Unknown','Security floor':s.security_floor,'Writable location':s.writable?'Yes':'No','Status':CHROMIUM_LABEL[s.status]||s.status})){
   const row=el('div','');row.append(el('b',k),el('strong',String(v)));box.append(row);}
  if(s.update_available){btn.disabled=false;btn.textContent='Update to revision '+s.available_revision}
  else{btn.disabled=true;btn.textContent=s.status==='UP_TO_DATE'?'Up to date':'Check again';}
  if(s.note)$('chromium-result').textContent=s.note;
 }catch(e){badge.textContent='UNAVAILABLE';$('chromium-result').textContent='Engine status unavailable.'}
}
async function chromiumUpdate(){const btn=$('chromium-update-btn'),res=$('chromium-result');
 btn.disabled=true;res.textContent='Downloading and verifying the approved Chromium build…';
 try{const force=$('chromium-force').checked;const r=await post('/api/chromium/update',{force});
  res.textContent='Update complete. Installed revision '+r.current_revision+'. '+(r.note||'');toast('Chromium engine updated');await chromiumRefresh();
 }catch(e){res.textContent='Update not completed: '+(e.message||'refused').replace('operation failed: ','HTTP ');toast('Chromium update not completed');btn.disabled=false}
}
async function init(){try{csrf=(await get('/api/session')).csrf}catch{location.reload();return}
 document.querySelectorAll('.nav').forEach(x=>x.addEventListener('click',()=>showView(x.dataset.view)));
 document.querySelectorAll('[data-goto]').forEach(x=>x.addEventListener('click',()=>showView(x.dataset.goto)));
 if($('target-form'))$('target-form').addEventListener('submit',diagnoseTarget);
 loadTarget();
 $('mark').addEventListener('click',mark);$('mark2').addEventListener('click',mark);
 $('selftest').addEventListener('click',selfTest);
 $('run-ai').addEventListener('click',async()=>{const target=$('ai-result');target.textContent='Running offline inference…';try{const x=await post('/api/ai-summary');target.textContent='AI hypotheses (not verified findings):\n'+x.analysis}catch{target.textContent='Local inference unavailable or timed out; no cloud fallback.'}});
 document.querySelectorAll('button.export').forEach(x=>x.addEventListener('click',()=>exportFile(x.dataset.preset)));
 $('event-filter').addEventListener('input',()=>renderEvents(lastEvents));
 $('chromium-update-btn').addEventListener('click',chromiumUpdate);
 document.querySelectorAll('.logtab').forEach(t=>t.addEventListener('click',()=>{logFilter=t.dataset.log;document.querySelectorAll('.logtab').forEach(x=>x.classList.toggle('active',x===t));renderLog(lastEvents)}));
 // bottom action bar mirrors existing tools
 $('act-incident').addEventListener('click',mark);
 $('act-selftest').addEventListener('click',()=>{showView('health');selfTest()});
 $('act-ai').addEventListener('click',()=>{showView('ai');$('run-ai').click()});
 $('act-updates').addEventListener('click',()=>{showView('updates');chromiumRefresh()});
 $('act-export').addEventListener('click',()=>showView('export'));
 $('capture-baseline').addEventListener('click',async()=>{if(!confirm('Save the currently retained approved evidence as a trusted reference baseline?'))return;try{await post('/api/baseline');await regression();toast('Trusted baseline saved')}catch{toast('Baseline failed')}});
 $('issue-form').addEventListener('submit',async e=>{e.preventDefault();try{await post('/api/known-issues',{fingerprint:$('issue-signature').value,ticket:$('issue-ticket').value,state:$('issue-state').value});await regression();toast('Known issue saved')}catch{toast('Invalid fingerprint, ticket or state')}});
 await refresh();setInterval(refresh,4000);
}
init();
