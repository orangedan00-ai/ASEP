
const $=id=>document.getElementById(id);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let dashboard=null, graphMode='asset', toastTimer, resourceTimer, resourceHistory=[];
async function api(path,opts={}){const r=await fetch(path,opts);let d;try{d=await r.json()}catch{d={error:await r.text()}}if(!r.ok||d?.ok===false)throw new Error(d?.error||`HTTP ${r.status}`);return d}
function toast(msg){const t=$('toast');t.textContent=msg;t.classList.add('show');clearTimeout(toastTimer);toastTimer=setTimeout(()=>t.classList.remove('show'),2600)}
function statusClass(s){s=String(s||'').toLowerCase();return s.includes('confirm')?'confirmed':s.includes('hypothesis')?'hypothesis':s.includes('indicator')?'indicator':s.includes('exploitable')?'exploitable':''}
const METRIC_ICONS={'TARGETS':'<circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>','SERVICES':'<rect x="4" y="4" width="16" height="6" rx="1.5"/><rect x="4" y="14" width="16" height="6" rx="1.5"/><circle cx="8" cy="7" r="1"/><circle cx="8" cy="17" r="1"/>','FINDINGS':'<path d="M12 3 2 20h20L12 3z"/><path d="M12 10v5"/><circle cx="12" cy="17.5" r=".6" fill="currentColor" stroke="none"/>','ATTACK PATHS':'<circle cx="5" cy="6" r="2.4"/><circle cx="19" cy="6" r="2.4"/><circle cx="12" cy="19" r="2.4"/><path d="M7 7.5 10.3 17M17 7.5 13.7 17M7.4 6h9.2"/>','SESSIONS':'<rect x="3" y="4" width="18" height="14" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/>','EVIDENCE ITEMS':'<path d="M5 3h10l4 4v14H5z"/><path d="M15 3v4h4"/><path d="M8 12h8M8 15.5h8M8 19h5"/>'};
const METRIC_ICON_DEFAULT='<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="2.2" fill="currentColor" stroke="none"/>';
function metricIcon(label){return `<svg class="metric-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${METRIC_ICONS[label]||METRIC_ICON_DEFAULT}</svg>`}
function metric(label,value,sub=''){return `<div class="metric"><span class="metric-icon-wrap">${metricIcon(label)}</span><div class="metric-body"><small>${esc(label)}</small><b>${esc(value)}</b><span>${esc(sub)}</span></div></div>`}
const PIPELINE_STAGES=[
  {id:'UNDERSTAND',title:'Understand',subtitle:'Scope, target & objective',views:['dashboard','missions']},
  {id:'DISCOVER',title:'Discover',subtitle:'Assets & attack surface',views:['network','targets','recon']},
  {id:'ANALYZE',title:'Analyze',subtitle:'Findings & relationships',views:['intelligence','deception','attack-paths']},
  {id:'VALIDATE',title:'Validate',subtitle:'Confirm & test',views:['validation']},
  {id:'EXPLOIT',title:'Exploit',subtitle:'Gain access (with approval)',views:['exploitation']},
  {id:'POST-EXPLOIT',title:'Post-Exploit',subtitle:'Enumerate, analyze, persist',views:['sessions','post-session']},
  {id:'ACHIEVE',title:'Achieve',subtitle:'Complete objective & report',views:['findings','evidence','timeline','reports']},
];
const VIEW_TO_STAGE={};PIPELINE_STAGES.forEach(s=>s.views.forEach(v=>VIEW_TO_STAGE[v]=s.id));
function renderPipeline(){$('pipeline').innerHTML=PIPELINE_STAGES.map((s,i)=>`<button class="pipeline-stage${i===0?' active':''}" data-pipeline="${s.id}" data-pipeline-view="${s.views[0]}" title="${esc(s.title)} — ${esc(s.subtitle)}"><span class="pipeline-num">${i+1}</span><span class="pipeline-text">${esc(s.title)}</span></button>`).join('')}
function showView(name){document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));const v=$(`view-${name}`);if(v)v.classList.add('active');document.querySelectorAll('.nav-item').forEach(b=>b.classList.toggle('active',b.dataset.view===name));if(window.innerWidth<850)$('sidebar').classList.remove('open');const stage=VIEW_TO_STAGE[name];document.querySelectorAll('[data-pipeline]').forEach(b=>b.classList.toggle('active',b.dataset.pipeline===stage));if(name==='targets'){loadTargets();loadEnvironment()}if(name==='network')loadNetwork(false);if(name==='attack-paths')loadPaths();if(name==='findings')loadFindings();if(name==='evidence')loadEvidence();if(name==='sessions')loadSessions();if(name==='timeline')loadActivity();if(name==='skills')loadSkills();if(name==='platform')loadHealth();if(name==='security')loadCapabilities();if(name==='wireless')loadWireless();if(name==='dashboard')loadDashboard();if(name==='autonomous'){loadAutonomousTargets()}if(name==='intelligence'){loadIntelligenceSummary();loadSkillOptions()}}
document.querySelectorAll('.nav-item').forEach(b=>b.addEventListener('click',()=>showView(b.dataset.view)));document.querySelectorAll('[data-view-jump]').forEach(b=>b.addEventListener('click',()=>showView(b.dataset.viewJump)));$('menuBtn').addEventListener('click',()=>$('sidebar').classList.toggle('open'));
const NODE_ICONS={'Firewall':'<path d="M12 3 4 6v6c0 5 3.4 8.4 8 9 4.6-.6 8-4 8-9V6z"/><path d="M8 11h8M8 14h8M10 8h4"/>','Router / Gateway':'<rect x="4" y="10" width="16" height="7" rx="1.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3M9 17v2M15 17v2M8 13.5h.01M12 13.5h.01M16 13.5h.01"/>','Network Switch':'<rect x="3" y="9" width="18" height="7" rx="1.5"/><path d="M6.5 16v2M11 16v2M15.5 16v2M6.5 9V7M11 9V7M15.5 9V7"/>','Wireless Access Point':'<path d="M5 12a10 10 0 0 1 14 0M8 15.3a6 6 0 0 1 8 0"/><circle cx="12" cy="19" r="1.1" fill="currentColor" stroke="none"/>','Printer':'<path d="M7 8V4h10v4M6 17H5a1 1 0 0 1-1-1v-5a1 1 0 0 1 1-1h14a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1h-1"/><rect x="7" y="14" width="10" height="6"/>','NAS / Storage':'<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>','Server / Host':'<rect x="4" y="4" width="16" height="6" rx="1.5"/><rect x="4" y="14" width="16" height="6" rx="1.5"/><circle cx="8" cy="7" r="1"/><circle cx="8" cy="17" r="1"/>','Laptop / Endpoint':'<rect x="5" y="5" width="14" height="9" rx="1"/><path d="M2 18h20l-1.5-2h-17z"/>','PC / Endpoint':'<rect x="4" y="4" width="16" height="11" rx="1.5"/><path d="M9 20h6M12 15v5"/>','Mobile Phone':'<rect x="7" y="2.5" width="10" height="19" rx="2"/><path d="M11 19h2"/>','Network Host':'<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="2.2" fill="currentColor" stroke="none"/>'};
function nodeIcon(type){return `<svg class="graph-node-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${NODE_ICONS[type]||NODE_ICONS['Network Host']}</svg>`}
function layoutRadial(nodes,edges){
  const idx={};nodes.forEach((n,i)=>idx[n.id]=i);
  const degree=new Array(nodes.length).fill(0),adj=nodes.map(()=>new Set());
  edges.forEach(e=>{const a=idx[e.from],b=idx[e.to];if(a===undefined||b===undefined||a===b)return;degree[a]++;degree[b]++;adj[a].add(b);adj[b].add(a)});
  let hub=0;for(let i=1;i<nodes.length;i++)if(degree[i]>degree[hub])hub=i;
  const pos={};
  if(nodes.length<=1||degree[hub]===0){
    const cols=Math.max(3,Math.ceil(Math.sqrt(nodes.length*1.3)));
    nodes.forEach((n,i)=>{pos[n.id]={x:(i%cols)*160+95,y:Math.floor(i/cols)*130+85}});
    return {pos,width:cols*160+80,height:Math.ceil(nodes.length/cols)*130+80};
  }
  pos[nodes[hub].id]={x:0,y:0};
  const ring1=[...adj[hub]];const visited=new Set([hub,...ring1]);const ring2=[];
  nodes.forEach((n,i)=>{if(!visited.has(i))ring2.push(i)});
  const place=(list,minR)=>{const n=list.length;if(!n)return minR;const nodeSpan=168;const r=Math.max(minR,(n*nodeSpan)/(2*Math.PI));list.forEach((i,k)=>{const ang=(k/n)*Math.PI*2-Math.PI/2;pos[nodes[i].id]={x:Math.round(Math.cos(ang)*r),y:Math.round(Math.sin(ang)*r)}});return r};
  const r1=place(ring1,190);place(ring2,r1+180);
  const xs=Object.values(pos).map(p=>p.x),ys=Object.values(pos).map(p=>p.y);
  const minX=Math.min(...xs)-95,minY=Math.min(...ys)-85,maxX=Math.max(...xs)+95,maxY=Math.max(...ys)+85;
  Object.values(pos).forEach(p=>{p.x-=minX;p.y-=minY});
  return {pos,width:maxX-minX,height:maxY-minY};
}
function renderGraph(data,boxId='attackGraph'){const box=$(boxId);const prevViewport=box.querySelector('.graph-viewport');const prevTransform=prevViewport?prevViewport.style.transform:'';box.innerHTML='';box.style.minWidth='';box.style.minHeight='';const nodes=data?.nodes||[],edges=data?.edges||[];if(!nodes.length){box.innerHTML='<div class="empty">No active assets discovered yet.</div>';return}const {pos,width:contentW,height:contentH}=layoutRadial(nodes,edges);const viewport=document.createElement('div');viewport.className='graph-viewport';viewport.style.width=contentW+'px';viewport.style.height=contentH+'px';edges.forEach(e=>{const a=pos[e.from],b=pos[e.to];if(!a||!b)return;const dx=b.x-a.x,dy=b.y-a.y;const rel=(e.relations||[]).join(' ').toLowerCase();const isHub=rel.includes('default-gateway');const line=document.createElement('div');line.className=`graph-edge ${String(e.status||'').toLowerCase().includes('hypothesis')?'hypothesis':''} ${isHub?'edge-hub':'edge-peer'}`;line.style.left=a.x+'px';line.style.top=a.y+'px';line.style.width=Math.hypot(dx,dy)+'px';line.style.transform=`rotate(${Math.atan2(dy,dx)}rad)`;viewport.appendChild(line)});nodes.forEach(n=>{const p=pos[n.id],d=document.createElement('button');d.type='button';const scopeRaw=String(n.status||'').toUpperCase();const scopeClass=scopeRaw==='IN-SCOPE'?'scope-in-scope':scopeRaw==='LOCAL-CANDIDATE'?'scope-local-candidate':'';const isTarget=n.kind==='target';d.className=`graph-node graph-node-${String(n.kind||'node').toLowerCase()} ${scopeClass}`;d.style.left=p.x+'px';d.style.top=p.y+'px';const type=n.type||'asset';const primary=n.hostname&&n.hostname.trim()?n.hostname:(isTarget?type:(n.label||n.id));const detail=isTarget?`${type}${n.brand?` (${n.brand})`:''} · ${n.vendor||'manufacturer unknown'}`:(n.detail||'');d.title=isTarget?`${primary} — ${n.label} · ${esc(n.status||'')}${n.asset_confidence?` · ${n.asset_confidence} confidence`:''}${n.brand?` · brand: ${esc(n.brand)}`:''}`:'';d.innerHTML=`${isTarget?nodeIcon(type):''}<b>${esc(primary)}</b><small>${esc(n.label||n.id)}</small>${detail&&primary!==type?`<small class="graph-node-sub">${esc(detail)}</small>`:''}`;d.addEventListener('click',e=>{if(box.dataset.dragging==='1'){e.preventDefault();return}if(n.kind==='target'||n.type==='target'||n.kind==='asset')openTargetDetail(n.id);else if(n.kind==='evidence'||n.type==='evidence')openEvidenceDetail(n.evidence_id||n.id);else if(n.target)openTargetDetail(n.target)});viewport.appendChild(d)});box.appendChild(viewport);const m=/translate\(([-\d.]+)px,\s*([-\d.]+)px\)/.exec(prevTransform||'');let tx=m?parseFloat(m[1]):0,ty=m?parseFloat(m[2]):0;requestAnimationFrame(()=>{const minTX=Math.min(0,box.clientWidth-contentW),minTY=Math.min(0,box.clientHeight-contentH);tx=Math.min(0,Math.max(minTX,tx));ty=Math.min(0,Math.max(minTY,ty));if(!prevTransform){tx=Math.round((box.clientWidth-contentW)/2);ty=Math.round((box.clientHeight-contentH)/2);tx=Math.min(0,Math.max(minTX,tx));ty=Math.min(0,Math.max(minTY,ty))}viewport.style.transform=`translate(${tx}px, ${ty}px)`});initGraphPan(box)}
function initGraphPan(box){if(box.dataset.panBound)return;box.dataset.panBound='1';let dragging=false,moved=false,startX=0,startY=0,startTX=0,startTY=0;
  box.addEventListener('pointerdown',e=>{const vp=box.querySelector('.graph-viewport');if(!vp)return;dragging=true;moved=false;box.classList.add('panning');startX=e.clientX;startY=e.clientY;const m=/translate\(([-\d.]+)px,\s*([-\d.]+)px\)/.exec(vp.style.transform||'');startTX=m?parseFloat(m[1]):0;startTY=m?parseFloat(m[2]):0;try{box.setPointerCapture(e.pointerId)}catch{}});
  box.addEventListener('pointermove',e=>{if(!dragging)return;const vp=box.querySelector('.graph-viewport');if(!vp)return;const dx=e.clientX-startX,dy=e.clientY-startY;if(Math.abs(dx)>4||Math.abs(dy)>4)moved=true;if(!moved)return;const minTX=Math.min(0,box.clientWidth-vp.offsetWidth),minTY=Math.min(0,box.clientHeight-vp.offsetHeight);const tx=Math.min(0,Math.max(minTX,startTX+dx)),ty=Math.min(0,Math.max(minTY,startTY+dy));vp.style.transform=`translate(${tx}px, ${ty}px)`});
  const end=()=>{if(!dragging)return;dragging=false;box.classList.remove('panning');if(moved){box.dataset.dragging='1';setTimeout(()=>{delete box.dataset.dragging},50)}};
  box.addEventListener('pointerup',end);box.addEventListener('pointercancel',end);box.addEventListener('pointerleave',()=>{if(dragging)end()});
}
function assetGraph(){return dashboard?.asset_graph||{nodes:[],edges:[]}}
function openModal(title,eyebrow,html){$('detailTitle').textContent=title;$('detailEyebrow').textContent=eyebrow;$('detailBody').innerHTML=html;$('detailModal').classList.add('show');$('detailModal').setAttribute('aria-hidden','false')}
function closeModal(){$('detailModal').classList.remove('show');$('detailModal').setAttribute('aria-hidden','true')}
function serviceRows(services){return (services||[]).map(p=>`<tr><td>${esc(p.port||'—')}</td><td>${esc(p.protocol||'—')}</td><td>${esc(p.state||'—')}</td><td><b>${esc(p.service||'Unknown')}</b></td><td>${esc([p.product,p.version].filter(Boolean).join(' ')||'—')}</td><td>${esc(p.detection||'Nmap -sV')}</td></tr>`).join('')}
async function openTargetDetail(target){
  try{
    const r=await api(`/api/v2/target/${encodeURIComponent(target)}`),t=r.target||{};
    const sources=(t.identity_sources||[]).map(x=>`<span class="pill">${esc(x.source||'source')}: ${esc(x.vendor||'')}</span>`).join(' ')||'<span class="pill">No local registry match</span>';
    const services=t.services||[];
    const serviceBlock=services.length?`<div class="table-wrap"><table><thead><tr><th>PORT</th><th>PROTO</th><th>STATE</th><th>SERVICE</th><th>PRODUCT / VERSION</th><th>DETECTION</th></tr></thead><tbody>${serviceRows(services)}</tbody></table></div><div class="button-row"><button class="secondary" onclick="runServiceDiscovery('${esc(t.address||target)}')">REFRESH SERVICE DISCOVERY</button></div>`:`<div class="empty small-empty">No open/identified service evidence stored for this target.</div><div class="button-row"><button class="primary" onclick="runServiceDiscovery('${esc(t.address||target)}')">RUN SERVICE DISCOVERY</button></div>`;
    openModal(t.address||target,'TARGET',`<div class="detail-summary"><div class="detail-hero"><div><b>${esc(t.address||target)}</b><small class="detail-subtitle">${esc(t.asset_type||'Network Host')} · ${esc(t.hostname||'hostname unresolved')}</small></div><span class="status">${esc(t.scope_status||'UNKNOWN')}</span></div>
      <div class="kv-list"><div class="kv"><span>ASSET TYPE</span><b>${esc(t.asset_type||'Network Host')} <small>${esc(t.asset_confidence||'low')} confidence</small></b></div><div class="kv"><span>HOSTNAME</span><b>${esc(t.hostname||'Hostname not resolved')}</b></div><div class="kv"><span>MANUFACTURER</span><b>${esc(t.vendor||'Manufacturer not resolved')}</b></div><div class="kv"><span>MAC</span><b>${esc(t.mac||'MAC unavailable')}</b></div><div class="kv"><span>NETWORK ROLE</span><b>${esc(t.role||'Unknown')} <small>${esc(t.role_confidence||'low')} · ${esc(t.role_basis||'insufficient evidence')}</small></b></div><div class="kv"><span>STATE</span><b>${esc(t.state||'unknown')}</b></div></div>
      <div class="detail-section"><div class="detail-section-head"><h3>Identity Sources</h3><span class="pill">multi-source</span></div><div class="button-row">${sources}</div></div>
      <div class="detail-section"><div class="detail-section-head"><h3>Observed Services</h3><span class="pill">${esc(t.service_count||0)} services</span></div>${serviceBlock}</div>
      <div class="detail-section"><div class="detail-section-head"><h3>Logical Topology</h3><span class="pill">${esc(t.topology?.role_confidence||'low')} confidence</span></div><div class="kv-list"><div class="kv"><span>DEFAULT GATEWAY</span><b>${esc(t.topology?.gateway||'—')}</b></div><div class="kv"><span>INTERFACE</span><b>${esc(t.topology?.interface||'—')}</b></div><div class="kv"><span>ROLE BASIS</span><b>${esc(t.topology?.role_basis||'—')}</b></div></div></div>
      <div class="detail-section"><div class="detail-section-head"><h3>Evidence</h3><span class="pill">${esc(t.evidence_count||0)}</span></div><div class="list">${(t.evidence||[]).slice(0,8).map(e=>`<button class="detail-link" onclick="openEvidenceDetail(${Number(e.id)})"><b>#${esc(e.id)} · ${esc(e.evidence_type)}</b><small>${esc(e.summary||'')} · ${esc(e.created_at||'')}</small></button>`).join('')||'<div class="empty small-empty">No evidence stored.</div>'}</div></div>
      <div class="panel-foot"><button class="primary" onclick="closeModal();showView('validation');$('validationTarget').value='${esc(t.address||target)}'">Open Validation</button>${t.metasploit_ready?`<button class="secondary" onclick="closeModal();openMetasploitForTarget('${esc(t.address||target)}')">METASPLOIT — AUTO MATCH</button>`:''}</div></div>`);
  }catch(e){toast(e.message)}
}
async function runServiceDiscovery(target){
  try{closeModal();showView('validation');$('validationTarget').value=target;await runTargetAction(target,'validate_services');await openTargetDetail(target);}
  catch(e){toast(e.message)}
}
async function openEvidenceDetail(id){
  try{const e=await api(`/api/evidence/${encodeURIComponent(id)}`);let data=e.data||'';try{data=JSON.stringify(JSON.parse(data),null,2)}catch{}openModal(`#${e.id} · ${e.evidence_type||'Evidence'}`,'EVIDENCE',`<div class="kv-list"><div class="kv"><span>TARGET</span><b>${esc(e.target||'—')}</b></div><div class="kv"><span>STATUS</span><b>${esc(e.status||'OBSERVED')}</b></div><div class="kv"><span>CREATED</span><b>${esc(e.created_at||'—')}</b></div><div class="kv"><span>SUMMARY</span><b>${esc(e.summary||'—')}</b></div></div><div class="detail-section"><h3>Raw Evidence</h3><pre class="result detail-raw">${esc(data)}</pre></div>`)}catch(e){toast(e.message)}
}
function resourceHealth(value){const v=Math.max(0,Math.min(100,Number(value)||0));if(v>=95)return {key:'critical',label:'CRITICAL'};if(v>=80)return {key:'high',label:'HIGH'};if(v>=60)return {key:'moderate',label:'MODERATE'};return {key:'low',label:'LOW'}}
function applyResourceHealth(cardId,valueId,barId,statusId,value){const h=resourceHealth(value);const card=$(cardId),label=$(valueId),bar=$(barId),status=$(statusId);if(!card||!label||!bar||!status)return;card.classList.remove('resource-low','resource-moderate','resource-high','resource-critical');card.classList.add('resource-'+h.key);label.textContent=`${Math.round(Math.max(0,Math.min(100,value)))}%`;bar.style.width=Math.min(Math.max(Number(value)||0,0),100)+'%';status.textContent=h.label}
async function loadResources(){try{const r=await api('/api/monitor');const cpu=Number(r.cpu_percent||0),mem=Number(r.memory_percent||0),disk=Number(r.disk_percent||0);$('resourceHost').textContent=r.host||'ASEP host';applyResourceHealth('resourceCpuCard','resourceCpuValue','resourceCpuBar','resourceCpuStatus',cpu);applyResourceHealth('resourceMemCard','resourceMemValue','resourceMemBar','resourceMemStatus',mem);applyResourceHealth('resourceDiskCard','resourceDiskValue','resourceDiskBar','resourceDiskStatus',disk);$('resourceNetValue').textContent=`↑ ${r.net_sent_mb} MB`;$('resourceNetDetail').textContent=`↓ ${r.net_recv_mb} MB · updated ${new Date(r.timestamp).toLocaleTimeString()}`;resourceHistory.push({cpu,mem});if(resourceHistory.length>40)resourceHistory.shift();drawResourceChart();$('resourceUpdated').textContent=new Date(r.timestamp).toLocaleTimeString()}catch(e){/* resource telemetry is non-critical */}}
function drawResourceChart(){const c=$('resourceChart');if(!c||!resourceHistory.length)return;const dpr=window.devicePixelRatio||1,w=c.clientWidth||600,h=90;c.width=w*dpr;c.height=h*dpr;const ctx=c.getContext('2d');ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,w,h);const healthColor=v=>v>=95?'#ff4f63':v>=80?'#f39a55':v>=60?'#f0bd5a':'#42d392';const line=(key,dash)=>{const latest=Number(resourceHistory[resourceHistory.length-1]?.[key]||0);ctx.beginPath();ctx.setLineDash(dash?[4,3]:[]);ctx.strokeStyle=healthColor(latest);resourceHistory.forEach((v,i)=>{const x=resourceHistory.length===1?w/2:i*(w/(resourceHistory.length-1));const y=h-6-(Math.min(100,v[key])/100)*(h-14);i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.stroke()};ctx.lineWidth=2;line('cpu',false);line('mem',true);ctx.setLineDash([])}
function renderMetrics(m){$('metrics').innerHTML=[metric('TARGETS',m.targets??0,`${m.live_hosts??0} currently responding`),metric('SERVICES',m.services??0,'observed services'),metric('FINDINGS',m.findings??0,'correlated findings'),metric('ATTACK PATHS',m.paths??0,'candidate paths'),metric('SESSIONS',m.sessions??0,'active sessions'),metric('EVIDENCE ITEMS',m.evidence??0,'stored observations')].join('')}
function renderFindings(items,boxId='dashboardFindings'){const box=$(boxId);if(!items?.length){box.innerHTML='<div class="empty">No findings available from current evidence.</div>';return}box.innerHTML=items.slice(0,8).map(f=>`<div class="list-item"><b>${esc(f.title)}</b><span class="status ${statusClass(f.status)}">${esc(f.status)}</span><small>${esc(f.target)} · confidence ${esc(f.confidence)}</small><small>${esc(f.detail||'')}</small></div>`).join('')}
function sessionStatusClass(s){s=String(s||'').toLowerCase();return s.includes('active')?'session-active':s.includes('sleep')?'session-sleeping':s.includes('dead')||s.includes('closed')||s.includes('lost')?'session-dead':''}
function renderSessions(items,boxId='dashboardSessions'){const box=$(boxId);if(!items?.length){box.innerHTML='<div class="empty">No active sessions.</div>';return}box.innerHTML=items.slice(0,8).map(s=>`<div class="list-item"><b>Session ${esc(s.id||s.session_id||'—')}</b><span class="session-status ${sessionStatusClass(s.status)}">${esc(s.status||'ACTIVE')}</span><small>${esc(s.target||s.host||'—')} · ${esc(s.type||s.session_type||'interactive')}</small></div>`).join('')}
function renderActivity(items,boxId='dashboardActivity'){const box=$(boxId);if(!items?.length){box.innerHTML='<div class="empty">No audit activity yet.</div>';return}box.innerHTML=items.slice(0,8).map(a=>`<div class="list-item"><b>${esc(a.action)}</b><small>${esc(a.target||'—')} · ${esc(a.status)}</small><small>${esc(a.created_at)}</small></div>`).join('')}
function renderLiveHosts(items){const box=$('dashboardLiveHosts');const live=(items||[]).filter(t=>['up','local','reachable'].includes(String(t.state||'').toLowerCase()));$('liveHostsStatus').textContent=`${live.length} LIVE`;if(!live.length){const diag=dashboard?.network_diagnostic;if(diag){box.innerHTML=`<div class="network-diagnostic network-diagnostic-${esc(diag.level)}"><b>${esc(diag.title)}</b><div class="diag-section"><label>Kemungkinan penyebab</label><ul>${diag.likely_causes.map(c=>`<li>${esc(c)}</li>`).join('')}</ul></div><div class="diag-section"><label>Langkah berikutnya</label><ul>${diag.next_steps.map(s=>`<li>${esc(s)}</li>`).join('')}</ul></div></div>`}else{box.innerHTML='<div class="empty">No active hosts discovered yet. Automatic discovery is running or waiting for the first cycle.</div>'}return}const portText=t=>{const ps=Array.isArray(t.ports)?t.ports:[];if(!ps.length)return '—';return ps.slice(0,24).map(p=>`${p.port}/${p.protocol||'tcp'}`).join(' · ')+(ps.length>24?` · +${ps.length-24} more`: '')};const scanMark=t=>{const err=deepScanFailedHosts[t.address];if(err)return `<span class="deep-scan-badge deep-scan-failed" title="${esc(err)}">⚠ DEEP SCAN FAILED</span>`;return t.deep_scanned?'<span class="deep-scan-badge" title="Services Deep Scan complete" aria-label="Deep scan complete">DEEP SCAN ✓</span>':''};box.innerHTML=`<div class="live-hosts-scroll"><table><thead><tr><th>IP</th><th>HOSTNAME</th><th>MANUFACTURER</th><th>ROLE</th><th>DEVICE</th><th>IDENTIFIED PORTS</th><th>STATE</th></tr></thead><tbody>${live.slice(0,100).map(t=>`<tr class="live-host-row" onclick="openTargetDetail('${esc(t.address)}')"><td>${scanMark(t)} <b>${esc(t.address)}</b></td><td>${esc(t.hostname||t.name||'—')}</td><td>${esc(t.vendor||'—')}</td><td>${esc(t.role||'Unknown')}</td><td>${esc(t.asset_type||'—')}${t.asset_brand?` · ${esc(t.asset_brand)}`:''}</td><td class="service-summary-cell">${esc(portText(t))}</td><td>${esc(t.state||'—')}</td></tr>`).join('')}</tbody></table></div>${live.length>100?`<div class="table-more">Showing first 100 of ${live.length} live hosts.</div>`:''}`}
async function startDeepScan(){if(!confirm('Run a FULL comprehensive TCP 1-65535 service scan (UDP is not scanned) now against all currently live hosts in the detected local network? This can be resource- and time-intensive.'))return;try{const r=await api('/api/deep-scan/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm_local_scope:true})});toast(r.message||`Deep scan started for ${r.count||0} hosts`);await loadDashboard()}catch(e){toast(e.message)}}
let lastDeepScanFinishedAt=0;
let deepScanFailedHosts={};
async function loadDeepScanStatus(){try{const r=await api('/api/deep-scan/status');const newFailed={};(r.failed_hosts||[]).forEach(f=>{if(f.target)newFailed[f.target]=f.error||'Deep scan failed'});const failedChanged=JSON.stringify(newFailed)!==JSON.stringify(deepScanFailedHosts);deepScanFailedHosts=newFailed;if(failedChanged){if(dashboard?.targets)renderLiveHosts(dashboard.targets);if($('targetsList'))loadTargets()}const box=$('deepScanSummary');if(!box)return;if(r.status==='running'){const pct=r.total?Math.round((r.completed/r.total)*100):0;const hostElapsed=r.current_started_at?Math.max(0,Math.round(Date.now()/1000-r.current_started_at)):0;const mins=Math.floor(hostElapsed/60),secs=hostElapsed%60;box.innerHTML=`<span>Deep scan RUNNING · ${r.completed}/${r.total} hosts · ${pct}% · current ${esc(r.current||'—')} · host ${mins}m ${secs}s · ${r.ports||0} observed ports</span>`}else if(r.status==='ready'||r.status==='ready_with_errors'){const partial=r.status==='ready_with_errors';box.innerHTML=`<span class="deep-scan-status-${partial?'partial':'complete'}">Deep scan ${partial?'COMPLETE WITH ERRORS':'COMPLETE'} · ${r.completed}/${r.total} hosts · ${r.ports||0} observed ports · ${r.services||0} identified services${partial?` · ${r.failed_hosts?.length||0} failed (lihat tanda ⚠ di tabel)`:''}</span>`;if(r.finished_at&&r.finished_at!==lastDeepScanFinishedAt){lastDeepScanFinishedAt=r.finished_at;setTimeout(()=>loadDashboard(),0)}}else if(r.status==='error'){box.innerHTML=`<span class="deep-scan-status-error">Deep scan ERROR · ${esc(r.error||'unknown error')}</span>`}else{box.innerHTML='<span>Waiting for automatic comprehensive scan after live-host discovery…</span>'}}catch(e){}}
async function loadDashboard(){try{dashboard=await api('/api/v2/dashboard');renderMetrics(dashboard.metrics);renderLiveHosts(dashboard.targets||[]);renderGraph(graphMode==='asset'?assetGraph():dashboard.attack_path);const r=dashboard.recommendations?.[0];$('recommendStatus').textContent=r?.status||'READY';$('recommendation').innerHTML=r?`<div class="rec-title">${esc(r.title)}</div><div class="confidence">Confidence <b>${esc(r.confidence)}</b></div>${(r.reason||[]).map(x=>`<div class="rec-reason">${esc(x)}</div>`).join('')}<div class="panel-foot"><button class="primary" onclick="executeRecommendation('${esc(r.action)}','${esc(r.target)}')">${r.action==='discover'?'DISCOVER':'REVIEW'}</button></div>`:'<div class="empty">No recommendation.</div>';renderFindings(dashboard.findings);renderSessions(dashboard.sessions);const act=await api('/api/v2/activity');renderActivity(act.activity);$('versionLabel').textContent='v'+dashboard.version;const env=dashboard.environment||{};const primary=env.primary||{};const ctx=env.context||{};const summary=dashboard.environment_summary||{};const network=primary.network||summary.network||'—';const localIp=primary.local_ip||ctx.local_ip||summary.local_ip||'—';const gateway=primary.gateway||ctx.gateway||summary.gateway||'—';const dns=(ctx.dns_servers||summary.dns_servers||[]).join(', ')||'—';const iface=primary.interface||summary.interface||'—';if($('dashboardEnvironment'))$('dashboardEnvironment').innerHTML=[['NETWORK',network],['LOCAL IP',localIp],['GATEWAY',gateway],['DNS',dns],['INTERFACE',iface]].map(x=>`<div class="environment-summary-item"><span>${esc(x[0])}</span><b>${esc(x[1])}</b></div>`).join('');const aw=dashboard.awareness||{};if($('awarenessStatus'))$('awarenessStatus').textContent=aw.service_running?'SERVICE SCANNING':(aw.last_started?'MONITORING':'STARTING');$('scopeValue').textContent=network!=='—'?network:((dashboard.scope||[]).join(', ')||'Auto local environment');$('scopeState').textContent=network!=='—'?'AUTO':'NOT DETECTED';await loadResources();await loadDeepScanStatus();}catch(e){toast(e.message)}}
async function executeRecommendation(action,target){if(action==='discover'&&target){showView('targets');await runTargetAction(target,'deep_recon')}else showView('findings')}
async function loadTargets(){try{const r=await api('/api/v2/targets');const box=$('targetsList');box.innerHTML=r.targets?.length?r.targets.map(t=>{const md=t.metadata||{};const hostname=md.hostname||t.name||'Hostname not resolved';const vendor=t.vendor||md.identity?.vendor||'Manufacturer not resolved';const mac=t.mac||md.identity?.mac_normalized||'MAC unavailable';const ports=Array.isArray(t.ports)?t.ports:[];const identified=ports.filter(p=>String(p.state||'').toLowerCase()==='open'||p.service);const portText=identified.length?identified.map(p=>`${p.port}/${p.protocol||'tcp'}`).join(' · '):'No identified ports';const msfReady=identified.some(p=>p.service||p.product||p.version);const deviceLine=t.asset_brand?`<small><strong>Device:</strong> ${esc(t.asset_type||'—')} · ${esc(t.asset_brand)}${t.asset_confidence?` (${esc(t.asset_confidence)} confidence)`:''}</small>`:'';return `<div class="target-card"><div class="target-title"><button class="detail-link target-main-link" onclick="targetDetails('${esc(t.address)}')"><b>${esc(t.address)}</b></button><div class="target-badges">${deepScanFailedHosts[t.address]?`<span class="deep-scan-badge deep-scan-failed" title="${esc(deepScanFailedHosts[t.address])}">⚠ DEEP SCAN FAILED</span>`:(t.deep_scanned?'<span class="deep-scan-badge">DEEP SCAN ✓</span>':'')}<span class="status">${esc(t.scope_status||t.scope||'UNKNOWN')}</span></div></div><small><strong>Hostname:</strong> ${esc(hostname)} · <strong>Manufacturer:</strong> ${esc(vendor)}</small>${deviceLine}<small><strong>MAC:</strong> ${esc(mac)}</small><small><strong>IDENTIFIED PORTS:</strong> ${esc(portText)}</small><small>${esc(t.role)} · ${esc(t.state)} · ${t.services} services · ${t.evidence} evidence · ${t.findings} findings</small>${msfReady?`<div class="button-row"><button class="secondary msf-action" onclick="event.stopPropagation();openMetasploitForTarget('${esc(t.address)}')">● METASPLOIT</button><button class="secondary" onclick="event.stopPropagation();loadExploitCandidates('${esc(t.address)}')">🔎 CEK KANDIDAT EXPLOIT</button></div><div id="exploitBox-${esc(t.address)}" class="exploit-candidates-box" onclick="event.stopPropagation()"></div>`:''}</div>`}).join(''):'<div class="empty large">No active-host inventory yet. Detect the current network and start host discovery.</div>';await loadEnvironment()}catch(e){toast(e.message)}}
function exploitConfidenceNote(){return '<div class="exploit-disclaimer">Semua hasil di bawah adalah KANDIDAT, bukan konfirmasi. Verifikasi manual + persetujuan scope tetap wajib sebelum tindakan apa pun.</div>'}
async function loadExploitCandidates(address){const box=$('exploitBox-'+address);if(!box)return;box.innerHTML='<div class="empty">Mengecek service, Metasploit lokal, dan referensi CVE internet…</div>';try{const r=await api('/api/v2/targets/'+encodeURIComponent(address)+'/exploit-candidates');if(!r.ok){box.innerHTML=`<div class="empty">${esc(r.error||'Gagal memuat kandidat exploit.')}</div>`;return}if(!r.services.length){box.innerHTML=`<div class="empty">Belum ada service dengan fingerprint versi yang pasti (${r.services_skipped_no_fingerprint} port dilewati). Jalankan Service Scan / Deep Scan dulu.</div>`;return}box.innerHTML=exploitConfidenceNote()+r.services.map(s=>{const msf=(s.local_msf||[]).map(m=>`<div class="exploit-item"><b>${esc(m.module)}</b><small class="status">${esc(m.status)}</small><small>${esc(m.note)}</small></div>`).join('');const cve=(s.internet_cve||[]).map(c=>`<div class="exploit-item"><b>${esc(c.id)}</b><small>Published: ${esc(c.published||'—')}</small><small>${esc(c.note)}</small></div>`).join('');const edb=(s.exploitdb||[]).map(e=>`<div class="exploit-item"><b>EDB-${esc(e.edb_id)}: ${esc(e.title)}</b><small>${esc(e.type||'—')} · ${esc(e.platform||'—')}</small><small>${esc(e.note)}</small></div>`).join('');const tools=(s.local_tools||[]).map(t=>`<span class="tool-chip ${t.installed?'installed':'missing'}">${esc(t.tool)}${t.installed?'':' (belum terpasang)'}</span>`).join('');const notes=(s.notes||[]).map(n=>`<div class="exploit-note">${esc(n)}</div>`).join('');const skillCtx=`Target ${address}, service ${s.service||'?'} (${s.product||''} ${s.version||''}) di port ${s.port}/${s.protocol}. Kandidat Metasploit lokal: ${(s.local_msf||[]).map(m=>m.module).join(', ')||'tidak ada'}. ExploitDB: ${(s.exploitdb||[]).map(e=>e.title).join(', ')||'tidak ada'}. Referensi CVE: ${(s.internet_cve||[]).map(c=>c.id).join(', ')||'tidak ada'}.`;return `<div class="exploit-service"><div class="exploit-service-head"><b>${esc(s.service||'service')} ${s.port?`(${esc(s.port)}/${esc(s.protocol)})`:''}</b><small>${esc(s.product)} ${esc(s.version)} · query: "${esc(s.query_used)}"</small></div>${msf?`<div class="exploit-group"><label>Metasploit lokal</label>${msf}</div>`:''}${edb?`<div class="exploit-group"><label>ExploitDB lokal</label>${edb}</div>`:''}${cve?`<div class="exploit-group"><label>Referensi CVE (internet)</label>${cve}</div>`:''}${tools?`<div class="exploit-group"><label>Tool lokal relevan</label><div class="tool-chips">${tools}</div></div>`:''}${notes}${(msf||cve||edb)?`<button class="secondary skill-link-btn" onclick="event.stopPropagation();runSkillReasoning(${JSON.stringify(skillCtx)},'vulnerability_correlation')">🧠 Analisis dengan Skill Reasoning</button>`:''}</div>`}).join('')}catch(e){box.innerHTML=`<div class="empty">${esc(e.message)}</div>`}}

async function loadEnvironment(){try{const r=await api('/api/environment');const box=$('environmentCandidates');const sel=$('discoveryNetwork');const candidates=r.candidates||[];if(sel){sel.innerHTML=candidates.length?candidates.map(c=>`<option value="${esc(c.network)}">${esc(c.network)} · ${esc(c.interface||'—')} · ${esc(c.kind||'unknown')}${c.primary?' · PRIMARY':''}</option>`).join(''):'<option value="">No local network detected</option>'}if(!candidates.length){box.innerHTML='<div class="empty">No active global IPv4 network candidate was detected.</div>';return}box.innerHTML=candidates.map(c=>`<div class="environment-card ${c.primary?'primary':''}"><b>${esc(c.network)}</b><small>${esc(c.interface||'—')} · ${esc(c.kind||'unknown')} · local ${esc(c.local_ip||'—')}</small><small>Gateway: ${esc(c.gateway||r.context?.gateway||'—')}</small><span class="status">${esc(c.scope_status||'LOCAL-CANDIDATE')}</span><div class="button-row"><button class="secondary" onclick="startDiscoveryFor('${esc(c.network)}')">DISCOVER HOSTS</button></div></div>`).join('')}catch(e){toast(e.message)}}
async function startDiscoveryFor(network){showView('network');await loadEnvironment();if($('discoveryNetwork'))$('discoveryNetwork').value=network;startDiscovery()}
async function startDiscovery(){const network=$('discoveryNetwork')?.value||'';if(!network)return toast('No local network candidate available');const method=$('discoveryMethod')?.value||'auto';const reverseDns=!!$('reverseDns')?.checked;$('discoveryRunState').textContent='RUNNING';$('discoveryStatusResult').textContent=`Starting host discovery on ${network}…`;try{const r=await api('/api/network-discovery/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({network,method,reverse_dns:reverseDns,confirm_local_scope:true})});$('discoveryStatusResult').textContent=JSON.stringify(r,null,2);toast(`Discovery started: ${network}`);pollDiscovery()}catch(e){$('discoveryRunState').textContent='ERROR';$('discoveryStatusResult').textContent=e.message;toast(e.message)}}
async function pollDiscovery(){try{const r=await api('/api/network-discovery/status');$('discoveryRunState').textContent=String(r.status||'IDLE').toUpperCase();if(r.status==='running'){setTimeout(pollDiscovery,1200);return}if(r.data){const d=r.data;$('discoveryStatusResult').textContent=`Network: ${d.network?.network||'—'}\nMethod: ${d.method||'—'}\nActive: ${d.active_count||0}\nNew: ${d.new_count||0}\nKnown: ${d.known_count||0}`;renderNetworkNodes(d.nodes||[]);await loadTargets();await loadHistory();await loadDashboard();toast(`Discovery complete: ${d.active_count||0} active host(s)`)}else if(r.error){$('discoveryStatusResult').textContent=r.error}}catch(e){setTimeout(pollDiscovery,1500)}}
async function loadHistory(){try{const r=await api('/api/network-discovery/history');const box=$('discoveryHistory');box.innerHTML=r.runs?.length?r.runs.map(x=>`<div class="list-item"><b>${esc(x.network)} · ${esc(x.status)}</b><small>${esc(x.interface||'—')} · ${esc(x.method||'auto')} · active ${esc(x.active_count||0)} · new ${esc(x.new_count||0)} · known ${esc(x.known_count||0)}</small><small>${esc(x.started_at||'')}</small></div>`).join(''):'<div class="empty">No discovery history yet.</div>'}catch(e){toast(e.message)}}
function renderNetworkNodes(nodes){const box=$('networkMap');box.innerHTML=nodes?.length?nodes.map(n=>{const id=n.identity||{};const hostname=n.hostname||n.name||'Hostname not resolved';const vendor=n.vendor||id.vendor||'Manufacturer not resolved';const mac=n.mac||id.mac_normalized||'MAC unavailable';const flags=id.mac_flags||{};const random=flags.randomized;return `<div class="network-node"><div class="network-node-head"><b>${esc(n.ip)}</b><span class="status">${esc(n.role||'unknown')}</span></div><div class="identity-row"><span>HOSTNAME</span><strong>${esc(hostname)}</strong></div><div class="identity-row"><span>MANUFACTURER</span><strong>${esc(vendor)}</strong></div><div class="identity-row"><span>MAC</span><strong>${esc(mac)}</strong></div>${random?'<div class="identity-note">Locally administered / randomized MAC — manufacturer cannot be reliably inferred from OUI.</div>':''}<small>${esc(n.state||'unknown')} · ${esc(n.interface||'—')} · ${esc(n.discovery_method||'discovery')}</small></div>`}).join(''):'<div class="empty large">No active hosts returned yet.</div>'}
async function openMetasploitForTarget(target){showView('exploitation');if($('msfTarget'))$('msfTarget').value=target;if($('msfQuery'))$('msfQuery').value='';$('msfIntelStatus').textContent='Loading persisted Target Inventory service intelligence…';$('msfTargetSummary').innerHTML='';$('msfServiceEvidence').innerHTML='';$('msfModules').innerHTML='<div class="empty">Searching Metasploit module metadata from persisted service evidence…</div>';try{await autoMetasploitSearch(target)}catch(e){toast(e.message)}}
async function autoMetasploitSearch(target){const t=String(target||$('msfTarget')?.value||'').trim();if(!t)return toast('No target selected');$('msfIntelStatus').textContent='Filtering remote CHECK-capable modules from Nmap OS/service evidence…';$('msfTargetSummary').innerHTML='';$('msfServiceEvidence').innerHTML='';$('msfModules').innerHTML='<div class="empty">Loading remote CHECK-capable candidates…</div>';try{const r=await api(`/api/v2/target/${encodeURIComponent(t)}/metasploit/candidates`);const services=r.services||[];$('msfTargetSummary').innerHTML=[['TARGET',r.target],['NMAP OS',r.os_label||'Unknown'],['OS CONFIDENCE',r.os_accuracy?`${r.os_accuracy}%`:'—'],['PLATFORM HINT',r.platform_hint||'unknown'],['SERVICES',r.service_count||0],['CHECKABLE MODULES',r.candidates?.length||0]].map(x=>`<div class="kv"><span>${esc(x[0])}</span><b>${esc(x[1])}</b></div>`).join('');$('msfServiceEvidence').innerHTML=services.slice(0,20).map(s=>`<div class="list-item"><b>${esc(s.port)}/${esc(s.protocol||'tcp')} · ${esc(s.service||'unknown')}</b><small>${esc([s.product,s.version].filter(Boolean).join(' ')||'Product/version unknown')}</small><small>Detection: ${esc(s.method||'nmap')} · confidence ${esc(s.confidence??'—')}</small></div>`).join('')||'<div class="empty">No persisted service intelligence.</div>';$('msfModules').innerHTML=(r.candidates||[]).map(m=>`<div class="list-item msf-candidate"><div class="msf-candidate-head"><b>${esc(m.module)}</b><span class="checkable-pill">CHECKABLE</span></div><small>REMOTE · ${esc(m.platforms?.join(', ')||'platform unknown')} · matched ${esc((m.matched_ports||[]).join(', ')||'—')}</small><small>${esc((m.matched_services||[]).join(', ')||'service unknown')} · RPORT ${esc(m.rport||'—')} · ${esc((m.match_reasons||[]).join(', ')||'evidence match')}</small><button class="secondary" onclick="selectModule('${esc(m.module)}','${esc(m.rport||'')}')">CHECK</button></div>`).join('')||'<div class="empty">No remote CHECK-capable exploit module matches the current Nmap OS/service evidence.</div>';$('msfIntelStatus').textContent=r.candidates?.length?`Found ${r.candidates.length} remote CHECK-capable module(s) matching ${r.os_label||r.platform_hint||'current'} evidence.`:'No remote CHECK-capable module matches current evidence.';toast(r.candidates?.length?`Found ${r.candidates.length} CHECK-capable remote candidate(s)`:'No CHECK-capable remote candidates');return r}catch(e){$('msfIntelStatus').textContent='Metasploit candidate search failed';throw e}}
async function targetDetails(target){await openTargetDetail(target)}
async function runTargetAction(target,action){try{const r=await api('/api/target/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,action})});$('validationResult').textContent=JSON.stringify(r,null,2);toast(`${action} completed`);await loadDashboard();}catch(e){$('validationResult').textContent=e.message;toast(e.message)}}
async function loadNetwork(refresh=false){try{await loadEnvironment();await loadHistory();const r=await api('/api/network-discovery/status');$('discoveryRunState').textContent=String(r.status||'IDLE').toUpperCase();if(r.data)renderNetworkNodes(r.data.nodes||r.data.active_hosts||[]);else if(r.error)$('discoveryStatusResult').textContent=r.error;else $('networkMap').innerHTML='<div class="empty large">Select a detected network and start host discovery.</div>'}catch(e){toast(e.message)}}
let lastPathsResult=null;
async function probeSession(controllerId, sessionId, platformHint='unknown'){const btn=event?.target;if(btn){btn.disabled=true;btn.textContent='Probing…'}try{const r=await api('/api/session/probe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({controller_id:controllerId,session_id:sessionId,platform:platformHint})});if(r.profile?.ok){toast(`Session probe OK: ${r.profile.os} / ${r.profile.privilege} / ${r.profile.user}`);await loadDemoAccounts()}else{toast(`Probe: ${r.profile?.error||r.error||'No session output'}`)}}catch(e){toast(e.message)}finally{if(btn){btn.disabled=false;btn.textContent='🔎 Probe Session'}}}
async function createDemoAccount(controllerId, sessionId, osName, privilege){if(!confirm(`Buat demo account pada ${osName} session ${sessionId}?\n\nAccount: asep_demo_<timestamp>\n\nINGAT: Cleanup HANYA bisa dilakukan oleh operator secara eksplisit, ASEP tidak akan otomatis menghapus account ini.`))return;try{const r=await api('/api/session/demo-account/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({controller_id:controllerId,session_id:sessionId,os:osName,privilege,dry_run:false})});const res=r.result;if(res.ok){toast(`Demo account dibuat: ${res.username}`);await loadDemoAccounts()}else{toast(`Demo account gagal: ${res.reason||'unknown error'}`)}}catch(e){toast(e.message)}}
async function loadDemoAccounts(){try{const r=await api('/api/session/demo-account/list');renderDemoAccounts(r.accounts||[])}catch(e){const box=$('demoAccountList');if(box)box.innerHTML=`<div class="empty">${esc(e.message)}</div>`}}
function renderDemoAccounts(accounts){const box=$('demoAccountList');if(!box)return;if(!accounts.length){box.innerHTML='<div class="empty">No demo accounts created in this session.</div>';return}box.innerHTML=accounts.map(a=>{const cleaned=a.cleanup_state==='CLEANUP_VERIFIED';return`<div class="demo-account-card ${cleaned?'demo-cleaned':'demo-active'}"><div class="demo-account-head"><b>${esc(a.username)}</b><span class="demo-status ${cleaned?'status-cleaned':'status-active'}">${esc(a.cleanup_state)}</span></div><div class="demo-account-meta"><small>Target: ${esc(a.target)} · OS: ${esc(a.os)} · Privilege: ${esc(a.privilege)}</small><small>Session: ${esc(a.session_id)} · Created: ${esc((a.created_at||'').slice(0,19))}</small>${a.cleanup_at?`<small>Cleaned: ${esc(a.cleanup_at.slice(0,19))} by ${esc(a.cleanup_by||'?')}</small>`:''}</div>${!cleaned?`<div class="button-row" style="margin-top:8px"><button class="secondary danger-btn" onclick="confirmDemoCleanup(${a.id},'${esc(a.username)}')">🗑 CLEANUP ACCOUNT</button></div><div class="demo-warning">⚠ Cleanup membutuhkan konfirmasi operator eksplisit. ASEP tidak akan menghapus account ini secara otomatis.</div>`:''}</div>`}).join('')}
async function confirmDemoCleanup(accountId, username){if(!confirm(`KONFIRMASI CLEANUP:\n\nAccount: ${username}\nID: ${accountId}\n\nIni adalah tindakan EKSPLISIT dari operator. Account akan dihapus dari target.\n\nLanjutkan?`))return;try{const r=await api(`/api/session/demo-account/${accountId}/cleanup`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:true})});toast(`Cleanup ${r.final_state}: ${username}`);await loadDemoAccounts()}catch(e){toast(e.message)}}
async function loadPaths(){try{const r=await api('/api/v2/attack-paths');lastPathsResult=r.result;renderGraph(r.result,'pathsGraph');const paths=r.result.paths||[];$('pathsList').innerHTML=paths.length?paths.map(p=>`<div class="list-item"><b>${esc(p.label)}</b><small>${esc(p.status)} · confidence ${esc(p.confidence||'—')}</small><small>Next: ${esc(p.next_validation||'—')}</small></div>`).join(''):'<div class="empty">No candidate path established.</div>';$('pathFindings').innerHTML=(r.result.findings||[]).map(f=>`<div class="list-item"><b>${esc(f.title)}</b><small>${esc(f.status)} · ${esc(f.target)}</small><small>${esc(f.detail||'')}</small></div>`).join('')||'<div class="empty">No path findings.</div>'}catch(e){toast(e.message)}}
function analyzePathsWithSkill(){const paths=lastPathsResult?.paths||[];if(!paths.length){toast('Belum ada candidate path untuk dianalisis');return}const ctx='Attack paths saat ini: '+paths.map(p=>`${p.label} (status ${p.status}, confidence ${p.confidence||'—'})`).join('; ');runSkillReasoning(ctx,'attack_path_intelligence')}
async function loadFindings(){try{const r=await api('/api/v2/findings');$('findingsList').innerHTML=r.findings?.length?r.findings.map(f=>`<div class="finding-card"><b>${esc(f.title)}</b><span class="status ${statusClass(f.status)}">${esc(f.status)}</span><small>${esc(f.target)} · confidence ${esc(f.confidence)}</small><small>Evidence: ${(f.evidence_ids||[]).join(', ')||'—'}</small><small>${esc(f.detail||'')}</small></div>`).join(''):'<div class="empty large">No findings available.</div>'}catch(e){toast(e.message)}}
async function loadEvidence(){try{const r=await api('/api/v2/evidence');$('evidenceList').innerHTML=r.evidence?.length?r.evidence.map(e=>`<div class="evidence-item"><b>#${e.id} · ${esc(e.evidence_type)}</b><span class="status ${statusClass(e.status)}">${esc(e.status)}</span><small>${esc(e.target)} · ${esc(e.created_at)}</small><small>${esc(e.summary||'')}</small><small>Confidence: ${esc(e.confidence)}</small></div>`).join(''):'<div class="empty large">No evidence stored.</div>'}catch(e){toast(e.message)}}
async function loadSessions(){try{const r=await api('/api/v2/sessions');$('sessionsList').innerHTML=r.sessions?.length?r.sessions.map(s=>`<div class="session-card"><b>Session ${esc(s.id||s.session_id||'—')}</b><small>Target: ${esc(s.target||s.host||'—')}</small><small>Type: ${esc(s.type||s.session_type||'—')} · Status: ${esc(s.status||'ACTIVE')}</small><div class="button-row"><button class="secondary" onclick="refreshSession('${esc(s.id||s.session_id||'')}')">Refresh</button></div></div>`).join(''):'<div class="empty large">No sessions.</div>'}catch(e){toast(e.message)}}
async function refreshSession(id){try{const r=await api('/api/metasploit/sessions/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});toast(`Session ${id} refreshed`);$('postSessionId').value=id;await loadSessions()}catch(e){toast(e.message)}}
async function loadActivity(){try{const r=await api('/api/v2/activity');$('timelineList').innerHTML=r.activity?.length?r.activity.map(a=>`<div class="timeline-item"><time>${esc(a.created_at)}</time><div><b>${esc(a.action)}</b><small>${esc(a.target||'—')} · ${esc(a.details||'')}</small></div><span class="status">${esc(a.status)}</span></div>`).join(''):'<div class="empty large">No activity.</div>'}catch(e){toast(e.message)}}
function capabilityAction(id){if(id==='wireless')showView('wireless');else if(id==='execution')showView('exploitation');else if(id==='evidence')showView('findings');else showView('missions')}
async function loadSkills(){try{const r=await api('/api/skills');$('skillsList').innerHTML=(r.skills||[]).map(s=>`<div class="cap-card"><b>${esc(s.id||s.name||'skill')}</b><small>${esc(s.description||s.category||'')}</small><small>Version: ${esc(s.version||'—')}</small></div>`).join('')||'<div class="empty">No skills.</div>'}catch(e){toast(e.message)}}
async function loadHealth(){try{const [m,h]=await Promise.all([api('/api/monitor'),api('/api/self-heal/health')]);$('healthCards').innerHTML=[metric('CPU',m.cpu_percent+'%','host'),metric('MEMORY',m.memory_percent+'%',`${m.memory_used_mb} / ${m.memory_total_mb} MB`),metric('DISK',m.disk_percent+'%',`${m.disk_used_gb} / ${m.disk_total_gb} GB`),metric('SELF-HEAL',h.result?.status||'READY','health')].join('');$('healResult').textContent=JSON.stringify(h.result,null,2)}catch(e){toast(e.message)}}
async function loadCapabilities(){try{const r=await api('/api/v2/capabilities');$('capabilityCards').innerHTML=r.families.map(c=>`<div class="cap-card"><b>${esc(c.title)}</b><small>${esc(c.description)}</small><button class="secondary" onclick="capabilityAction('${esc(c.id)}')">Open</button></div>`).join('')}catch(e){toast(e.message)}}
async function loadWireless(){try{const r=await api('/api/wireless/interfaces');$('wifiInterfaces').innerHTML=(r.interfaces||[]).map(i=>`<div class="list-item"><b>${esc(i.name)}</b><small>${esc(i.type||'wireless')}</small></div>`).join('')||'<div class="empty">No wireless interface.</div>'}catch(e){$('wifiInterfaces').innerHTML=`<div class="list-item">${esc(e.message)}</div>`}}
async function scanWireless(){try{const iface=document.querySelector('#wifiInterfaces .list-item b')?.textContent||'';const r=await api('/api/wireless/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({interface:iface,method:'nmcli'})});$('wifiNetworks').innerHTML=(r.aps||[]).map(a=>`<div class="list-item"><b>${esc(a.ssid||'(hidden)')}</b><small>${esc(a.bssid||'—')} · ${esc(a.security||'OPEN')} · ${esc(a.channel||'—')}</small></div>`).join('')||'<div class="empty">No networks detected.</div>';toast('Wireless scan complete');await loadEvidence()}catch(e){toast(e.message)}}
async function runWirelessPath(){try{const r=await api('/api/wireless/attack-path');$('wirelessPathResult').innerHTML=(r.findings||[]).map(f=>`<div class="list-item"><b>${esc(f.title)}</b><small>${esc(f.status)} · ${esc(f.target)}</small><small>${esc(f.detail||'')}</small></div>`).join('')||`<div class="list-item"><b>${esc(r.status||'NO_DATA')}</b><small>${esc((r.notes||[]).join(' '))}</small></div>`;toast('Wireless attack-path analysis complete')}catch(e){toast(e.message)}}
function readinessClass(status){return String(status||'').toLowerCase().replace(/[^a-z_]+/g,'-')}
function renderIntelSummary(d){
  const sum=d.summary||{}; const env=d.environment||{}; const ready=d.readiness||[];
  $('intelEnvironment').textContent=env.network||'UNKNOWN NETWORK';
  $('intelReadinessState').textContent=ready.find(x=>x.status==='NEEDS_MORE_EVIDENCE')?'NEEDS EVIDENCE':(ready.every(x=>x.status==='COMPLETE'||x.status==='READY')?'READY':'IN PROGRESS');
  $('intelMetrics').innerHTML=[['ACTIVE HOSTS',sum.active_hosts||0,'discovered'],['IDENTIFIED',sum.identified_hosts||0,'identity evidence'],['SERVICES',sum.service_hosts||0,'service evidence'],['PLATFORM',sum.platform_hosts||0,'role/platform evidence'],['CONFIRMED',sum.findings_confirmed||0,'validated findings'],['PATHS',sum.attack_paths||0,'candidate paths']].map(x=>metric(x[0],x[1],x[2])).join('');
  $('intelPipeline').innerHTML=ready.map((r,i)=>`<button type="button" class="intel-stage ${readinessClass(r.status)}" data-stage="${esc(r.id)}"><span>${i+1}</span><b>${esc(r.title)}</b><small>${esc(r.status.replaceAll('_',' '))}</small></button>`).join('');
  const types=d.asset_types||[], roles=d.roles||[];
  $('intelUnderstanding').innerHTML=`<div class="intel-under-grid"><div><h3>Asset Types</h3>${types.map(x=>`<div class="intel-count"><span>${esc(x.label)}</span><b>${x.count}</b></div>`).join('')||'<div class="small-empty">No asset classification yet.</div>'}</div><div><h3>Network Roles</h3>${roles.map(x=>`<div class="intel-count"><span>${esc(x.label)}</span><b>${x.count}</b></div>`).join('')||'<div class="small-empty">No role evidence yet.</div>'}</div></div>`;
  const n=d.next_best_action||{}; $('intelNextStatus').textContent=n.status||'READY'; $('intelNextAction').innerHTML=`<div class="rec-title">${esc(n.title||'No next action')}</div>${(n.reason||[]).map(x=>`<div class="rec-reason">${esc(x)}</div>`).join('')}<div class="intel-action-label">Action: <b>${esc(n.action||'analyze')}</b></div>`;
  const gaps=d.gaps||[]; $('intelGaps').innerHTML=gaps.length?gaps.map(g=>`<div class="list-item"><b>${esc(g.title)} · ${g.count}</b><small>${esc(g.detail)}</small></div>`).join(''):'<div class="empty small-empty">No material knowledge gaps detected.</div>';
}
async function loadIntelligenceSummary(){try{const d=await api('/api/v2/intelligence/summary');renderIntelSummary(d);const ev=await api('/api/v2/evidence');const items=(ev.evidence||[]).slice(0,10);$('intelEvidenceCount').textContent=ev.evidence?.length||0;$('intelEvidence').innerHTML=items.map(e=>`<button class="detail-link" onclick="openEvidenceDetail(${e.id})"><b>#${e.id} ${esc(e.evidence_type)}</b><small>${esc(e.status)} · ${esc(e.target)}</small></button>`).join('')||'<div class="empty small-empty">No evidence stored yet.</div>';}catch(e){$('intelReadinessState').textContent='ERROR';$('intelNextAction').innerHTML=`<div class="list-item">${esc(e.message)}</div>`}}
async function loadSkillOptions(){const sel=$('skillReasonSelect');if(!sel||sel.dataset.loaded)return;try{const r=await api('/api/skills');sel.innerHTML='<option value="">Auto (pilih otomatis dari konteks)</option>'+r.skills.map(s=>`<option value="${esc(s.id)}">${esc(s.title)}</option>`).join('');sel.dataset.loaded='1'}catch(e){}}
async function runSkillReasoning(prefillContext,prefillSkillId){if(prefillContext!==undefined){showView('intelligence');await loadSkillOptions();if($('skillReasonContext'))$('skillReasonContext').value=prefillContext;if($('skillReasonSelect'))$('skillReasonSelect').value=prefillSkillId||''}const ctx=$('skillReasonContext')?.value?.trim();if(!ctx){toast('Isi context dulu (evidence/target/tujuan)');return}const skillId=$('skillReasonSelect')?.value||null;const btn=$('skillReasonRun');const box=$('skillReasonResult');if(btn){btn.disabled=true;btn.textContent='Menjalankan…'}if(box)box.innerHTML='<div class="empty">Menjalankan reasoning…</div>';try{const r=await api('/api/skills/reason',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({context:ctx,skill_ids:skillId?[skillId]:null})});if($('skillReasonMode'))$('skillReasonMode').textContent=(r.mode||'none').toUpperCase();const usedSkills=(r.skill_ids||[]).join(', ');if(box)box.innerHTML=r.mode==='none'?`<div class="empty">${esc(r.text||'LLM belum dikonfigurasi.')}</div>`:`<div class="intel-block"><b>Skill dipakai: ${esc(usedSkills)}</b><div>${esc(r.text||'')}</div></div>`}catch(e){if(box)box.innerHTML=`<div class="list-item">${esc(e.message)}</div>`;toast(e.message)}finally{if(btn){btn.disabled=false;btn.textContent='Jalankan Reasoning'}}}
async function runIntelligence(){try{await loadIntelligenceSummary();const readiness=await api('/api/v2/intelligence/summary');const analysisStage=(readiness.readiness||[]).find(x=>x.id==='analysis');if(analysisStage?.status==='LOCKED'){toast('Complete discovery, identity, service and platform evidence first');return}$('intelOutput').innerHTML='<div class="empty">Analyzing collected evidence...</div>';$('intelDeepState').textContent='RUNNING';const r=await api('/api/intelligence/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({use_cloud:true,use_local:true})});$('intelMode').textContent=r.mode||'LOCAL';$('intelDeepState').textContent='COMPLETE';const blocks=[];if(r.local?.text)blocks.push(`<div class="intel-block"><b>Local Intelligence</b><div>${esc(r.local.text)}</div></div>`);if(r.cloud?.text)blocks.push(`<details class="intel-raw"><summary>Cloud / engine details</summary><pre class="result">${esc(r.cloud.text)}</pre></details>`);if(!blocks.length)blocks.push(`<details class="intel-raw"><summary>Raw engine response</summary><pre class="result">${esc(JSON.stringify(r,null,2))}</pre></details>`);$('intelOutput').innerHTML=blocks.join('');toast('Intelligence analysis complete');await loadIntelligenceSummary();await loadDashboard()}catch(e){$('intelDeepState').textContent='ERROR';$('intelOutput').innerHTML=`<div class="list-item">${esc(e.message)}</div>`;toast(e.message)}}
async function runNvd(){try{const q=$('nvdQuery').value.trim();if(!q)return toast('Enter a research query');const r=await api('/api/research/nvd',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:q,limit:8})});$('nvdResult').innerHTML=(r.vulnerabilities||r.results||r.data||[]).map(x=>`<div class="list-item"><b>${esc(x.id||x.cve?.id||x.title||'CVE')}</b><small>${esc(x.description||x.summary||'')}</small></div>`).join('')||`<pre class="result">${esc(JSON.stringify(r,null,2))}</pre>`}catch(e){toast(e.message)}}
async function runDeception(){try{const obs=$('deceptionObs').value.split('\n').map(x=>x.trim()).filter(Boolean);const r=await api('/api/deception/assess',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:$('deceptionTarget').value.trim(),observations:obs})});$('deceptionResult').textContent=JSON.stringify(r.result,null,2)}catch(e){$('deceptionResult').textContent=e.message}}
async function recommendMission(){try{const evidence=$('missionEvidence').value.split('\n').map(x=>x.trim()).filter(Boolean);const env=[$('missionTarget').value.trim()].filter(Boolean);const r=await api('/api/capabilities/recommend',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({objective:$('missionObjective').value.trim(),evidence,environment:env})});$('missionResult').innerHTML=(r.capabilities||[]).map(c=>`<div class="cap-card"><b>${esc(c.name||c.capability||c.id||'Capability')}</b><small>${esc(c.reason||c.description||JSON.stringify(c))}</small></div>`).join('')||`<pre class="result">${esc(JSON.stringify(r,null,2))}</pre>`}catch(e){toast(e.message)}}
async function runValidation(action){const t=$('validationTarget').value.trim();if(!t)return toast('Enter a target');await runTargetAction(t,action)}
async function msfSearch(){try{const r=await api('/api/metasploit/search',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:$('msfQuery').value.trim(),limit:20})});$('msfModules').innerHTML=(r.result||[]).map(m=>`<div class="list-item"><b>${esc(m.name||m.module||m.path||'module')}</b><small>${esc(JSON.stringify(m))}</small><button class="secondary" onclick="selectModule('${esc(m.name||m.module||m.path||'')}')">Select</button></div>`).join('')||'<div class="empty">No modules returned.</div>'}catch(e){toast(e.message)}}
function selectModule(m,rport){$('msfModule').value=m;if($('msfRport'))$('msfRport').value=rport||'';showView('exploitation')}
async function msfCheck(){const target=$('msfTarget').value.trim(),module=$('msfModule').value.trim(),rport=$('msfRport')?.value.trim()||'';if(!target||!module){toast('Select a CHECK-capable remote module first');return}const panel=$('msfCheckPanel'),raw=$('msfResult');if(panel)panel.innerHTML='<div class="check-state running"><span class="spinner-dot"></span>CHECK running…</div>';if(raw)raw.textContent='';$('msfRun').disabled=true;$('msfRun').textContent='RUN — LOCKED: CHECK REQUIRED';try{const r=await api('/api/metasploit/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,module,rport})});const result=r.result||{};const status=String(result.status||'UNKNOWN').toUpperCase();const reason=status==='VULNERABLE'?'Target reported VULNERABLE by module check.':status==='NOT_VULNERABLE'?'Module check reported NOT VULNERABLE.': 'Module check was inconclusive or could not determine state.';if(panel)panel.innerHTML=`<div class="check-state ${status.toLowerCase()}"><div class="check-state-title">${esc(status.replace('_',' '))}</div><div>${esc(reason)}</div><small>Target ${esc(target)} · RPORT ${esc(result.rport||rport||'—')} · ${esc(result.elapsed_sec||'—')}s</small></div>`;if(raw)raw.textContent=result.output||'';const vuln=status==='VULNERABLE';$('msfRun').disabled=!vuln;$('msfRun').textContent=vuln?'RUN — EXPLICIT APPROVAL REQUIRED':`RUN — LOCKED: ${status.replace('_',' ')}`;toast(vuln?'CHECK: VULNERABLE — RUN available after approval':`CHECK: ${status} — RUN remains locked`)}catch(e){if(panel)panel.innerHTML=`<div class="check-state error"><div class="check-state-title">CHECK ERROR</div><div>${esc(e.message)}</div></div>`;if(raw)raw.textContent=e.message;$('msfRun').disabled=true;$('msfRun').textContent='RUN — LOCKED: CHECK ERROR';toast(e.message)}}
async function msfRun(){if(!confirm('Explicitly approve Metasploit RUN for the selected target/module?'))return;try{const r=await api('/api/metasploit/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:$('msfTarget').value.trim(),module:$('msfModule').value.trim(),rport:$('msfRport')?.value.trim()||'',approval:true})});$('msfResult').textContent=JSON.stringify(r.result,null,2);toast('Metasploit RUN completed');await loadSessions()}catch(e){toast(e.message)}}
async function postAdvice(){try{const r=await api('/api/post-session/advice',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:$('postSessionId').value.trim(),target:$('postTarget').value.trim(),platform:$('postPlatform').value.trim(),privilege:$('postPrivilege').value.trim()})});$('postResult').textContent=JSON.stringify(r.result,null,2)}catch(e){$('postResult').textContent=e.message}}
async function modifyPreview(){try{const changes=JSON.parse($('modifyChanges').value||'{}');const r=await api('/api/self-modifying/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({changes})});$('modifyResult').textContent=JSON.stringify(r.result,null,2)}catch(e){$('modifyResult').textContent=e.message}}
async function toolInventory(){try{const r=await api('/api/tools');$('toolControlResult').textContent=JSON.stringify(r,null,2)}catch(e){$('toolControlResult').textContent=e.message}}
async function toolPlan(){try{const target=$('toolTarget').value.trim();const r=await api('/api/tools/plan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target})});$('toolControlResult').textContent=JSON.stringify(r,null,2)}catch(e){$('toolControlResult').textContent=e.message}}
async function toolRun(){try{const target=$('toolTarget').value.trim();const tool=$('toolName').value.trim();const profile=$('toolProfile').value.trim();const r=await api('/api/tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,tool,profile})});$('toolControlResult').textContent=JSON.stringify(r,null,2);await loadDashboard()}catch(e){$('toolControlResult').textContent=e.message}}
async function evidenceChain(){try{const target=$('toolTarget').value.trim();const r=await api('/api/tools/execute-chain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,depth:'standard'})});$('toolControlResult').textContent=JSON.stringify(r,null,2);await loadDashboard()}catch(e){$('toolControlResult').textContent=e.message}}
async function passiveDeepDiveUI(){try{const target=$('reasonTarget').value.trim();const observations=JSON.parse($('reasonObservations').value||'[]');const r=await api('/api/target-path/passive-deep-dive',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,scope_status:'UNKNOWN',evidence:observations,relationships:[]})});$('reasonControlResult').textContent=JSON.stringify(r,null,2)}catch(e){$('reasonControlResult').textContent=e.message}}
async function adaptiveAnalyzeUI(){try{const target=$('reasonTarget').value.trim();const observations=JSON.parse($('reasonObservations').value||'[]');const r=await api('/api/adaptive/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,observations,nodes:[],edges:[]})});$('reasonControlResult').textContent=JSON.stringify(r,null,2)}catch(e){$('reasonControlResult').textContent=e.message}}
async function replanUI(){try{const objective=$('missionObjective').value.trim();const failed_actions=JSON.parse($('replanFailed').value||'[]');const r=await api('/api/replan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({objective,failed_actions,blocked_paths:[],evidence:[]})});$('reasonControlResult').textContent=JSON.stringify(r,null,2)}catch(e){$('reasonControlResult').textContent=e.message}}
async function windowsFingerprintUI(){try{const target=$('windowsTarget').value.trim();const r=await api('/api/windows/fingerprint',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target})});$('platformControlResult').textContent=JSON.stringify(r,null,2)}catch(e){$('platformControlResult').textContent=e.message}}
async function wirelessChainUI(){try{const iface=$('wirelessInterface').value.trim();const r=await api('/api/wireless/chain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({interface:iface||null})});$('platformControlResult').textContent=JSON.stringify(r,null,2)}catch(e){$('platformControlResult').textContent=e.message}}
async function shellRunUI(){try{const command=$('shellCommand').value.trim();const r=await api('/api/shell',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({command})});$('systemControlResult').textContent=JSON.stringify(r,null,2)}catch(e){$('systemControlResult').textContent=e.message}}
async function sudoRunUI(){if(!confirm('Approve this command for sudo/root execution? The password is entered by you in the PTY and is never sent to ASEP/LLM.'))return;try{const command=$('shellCommand').value.trim();const r=await api('/api/sudo',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({command,approved:true})});$('systemControlResult').textContent=JSON.stringify(r,null,2)}catch(e){$('systemControlResult').textContent=e.message}}
async function selfModifyApplyUI(){if(!confirm('Apply the proposed self-modifying changes? ASEP will checkpoint, compile, test and roll back on failure.'))return;try{const changes=JSON.parse($('selfModifyChanges').value||'{}');const r=await api('/api/self-modifying/apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({changes,approval:true,run_tests:true})});$('systemControlResult').textContent=JSON.stringify(r,null,2)}catch(e){$('systemControlResult').textContent=e.message}}
const LLM_MODE_LABEL={cloud:'Cloud',local:'Local',claude_code:'Claude Code',none:'Not configured'};
const LLM_MODE_CLASS={cloud:'llm-mode-cloud',local:'llm-mode-local',claude_code:'llm-mode-claude',none:'llm-mode-none'};
const INTERNET_ICON={ONLINE:'🌐',OFFLINE:'✗',CHECKING:'…'};
async function refreshLlmStatusBadge(){const el=$('dashboardLlmStatus');const sub=$('dashboardLlmSub');if(!el)return;try{const i=await api('/api/intelligence/status');const mode=i.mode||'none';const ph=i.provider_health||{};const internet=i.internet||'CHECKING';const task=ph.current_task||'';const age=ph.last_check_age_s!=null?`${ph.last_check_age_s}s ago`:'';el.textContent=`${INTERNET_ICON[internet]||'?'} LLM: `+(LLM_MODE_LABEL[mode]||mode)+(task?` · ${task}`:'');el.className='pill llm-status-pill '+(LLM_MODE_CLASS[mode]||'');el.onclick=()=>showView('settings');if(sub){const activeState=ph[mode==='cloud'?'cloud':mode==='claude_code'?'claude_code':'local_llm']||'—';sub.textContent=`${activeState}${age?' · '+age:''}`;sub.className=`llm-sub-state llm-sub-${String(activeState).toLowerCase()}`}}catch{el.textContent='LLM: status unavailable';el.className='pill llm-status-pill llm-mode-none';el.onclick=()=>showView('settings')}}
async function loadSettings(){try{const [s,i,p]=await Promise.all([api('/api/status'),api('/api/intelligence/status'),api('/api/privilege')]);const cc=i.claude_code||{};const ph=i.provider_health||{};const internet=i.internet||'CHECKING';const ccLine=cc.enabled?(cc.installed?`enabled, CLI found (${cc.binary_path})`:'enabled, but CLI NOT found in PATH'):(cc.installed?'CLI found, not enabled (set ASEP_CLAUDE_CODE_ENABLED=true)':'not installed');const phLine=`Local LLM: ${ph.local_llm||'—'} · Cloud: ${ph.cloud||'—'} · Claude Code: ${ph.claude_code||'—'}`;$('settingsRuntime').innerHTML=[['Version',s.version],['LLM mode (active now)',i.mode],['Internet',internet],['Provider health',phLine],['Cloud model',i.cloud?.model],['Local model',i.local?.model],['Claude Code',ccLine],['Root approval',p.root_approval_required?'REQUIRED':'UNKNOWN'],['Scope',(s.scope||[]).join(', ')||'Not configured'],['Self-modify','DISABLED BY DEFAULT']].map(x=>`<div class="kv"><span>${esc(x[0])}</span><b>${esc(x[1])}</b></div>`).join('');if($('llmModeSelect'))$('llmModeSelect').value=i.requested_mode||'auto';if($('llmModeNote'))$('llmModeNote').textContent=`Sedang aktif: ${i.mode}`;const cup=$('claudeUsagePanel');if(cup){if(cc.enabled&&cc.installed){cup.innerHTML='<div class="kv"><span>Claude Usage</span><b>Estimasi: tidak tersedia dari sini</b></div><div class="kv" style="font-size:9px;color:var(--muted)"><span></span><span>Claude Code memakai sesi OAuth Anda sendiri — ASEP tidak bisa membaca kuota. Cek di claude.ai/usage.</span></div>'}else{cup.innerHTML=''}}}catch(e){toast(e.message)}}
async function applyLlmMode(){const sel=$('llmModeSelect');const btn=$('llmModeApply');if(!sel)return;const mode=sel.value;btn.disabled=true;btn.textContent='Menerapkan…';try{const r=await api('/api/settings/llm-mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode})});toast(`LLM mode diganti ke ${mode} (aktif sekarang: ${r.active_mode})`+(r.persisted_to_env?'':' — PERINGATAN: gagal disimpan ke .env, akan kembali ke setelan lama setelah restart'));await loadSettings();await refreshLlmStatusBadge()}catch(e){toast(e.message)}finally{btn.disabled=false;btn.textContent='Terapkan'}}
$('pipeline').addEventListener('click',e=>{const b=e.target.closest('[data-pipeline-view]');if(b)showView(b.dataset.pipelineView)});
$('deepScanBtn').addEventListener('click',startDeepScan);$('closeDetail').addEventListener('click',closeModal);$('detailModal').addEventListener('click',e=>{if(e.target.id==='detailModal')closeModal()});document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal()});$('refreshAll').addEventListener('click',loadDashboard);$('discoverNetwork').addEventListener('click',()=>showView('network'));$('refreshEnvironment').addEventListener('click',loadEnvironment);$('startDiscovery').addEventListener('click',startDiscovery);$('refreshNetwork').addEventListener('click',()=>loadNetwork(true));$('refreshHistory').addEventListener('click',loadHistory);$('refreshPaths').addEventListener('click',loadPaths);$('refreshFindings').addEventListener('click',loadFindings);$('refreshEvidence').addEventListener('click',loadEvidence);$('refreshSessions').addEventListener('click',loadSessions);$('runIntelligence').addEventListener('click',runIntelligence);$('runNvd').addEventListener('click',runNvd);$('runDeception').addEventListener('click',runDeception);$('recommendMission').addEventListener('click',recommendMission);$('msfAutoSearch').addEventListener('click',()=>autoMetasploitSearch($('msfTarget').value.trim()));$('msfCheck').addEventListener('click',msfCheck);$('msfRun').addEventListener('click',msfRun);$('postAdvice').addEventListener('click',postAdvice);$('modifyPreview').addEventListener('click',modifyPreview);$('refreshHealth').addEventListener('click',loadHealth);$('scanWireless').addEventListener('click',scanWireless);$('wirelessPath').addEventListener('click',runWirelessPath);$('toolInventoryBtn').addEventListener('click',toolInventory);$('toolPlanBtn').addEventListener('click',toolPlan);$('toolRunBtn').addEventListener('click',toolRun);$('chainRunBtn').addEventListener('click',evidenceChain);$('passiveDeepDiveBtn').addEventListener('click',passiveDeepDiveUI);$('adaptiveAnalyzeBtn').addEventListener('click',adaptiveAnalyzeUI);$('replanBtn').addEventListener('click',replanUI);$('windowsFingerprintBtn').addEventListener('click',windowsFingerprintUI);$('wirelessChainBtn').addEventListener('click',wirelessChainUI);$('shellRunBtn').addEventListener('click',shellRunUI);$('sudoRunBtn').addEventListener('click',sudoRunUI);$('selfModifyApplyBtn').addEventListener('click',selfModifyApplyUI);document.querySelectorAll('[data-validation-action]').forEach(b=>b.addEventListener('click',()=>runValidation(b.dataset.validationAction)));document.querySelectorAll('[data-graph-mode]').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('[data-graph-mode]').forEach(x=>x.classList.remove('active'));b.classList.add('active');graphMode=b.dataset.graphMode;if(dashboard)renderGraph(graphMode==='asset'?assetGraph():dashboard.attack_path)}));
renderPipeline();loadDashboard();loadSettings();refreshLlmStatusBadge();setInterval(async()=>{if(document.visibilityState!=='visible')return;try{await loadDashboard();await loadDeepScanStatus();await refreshLlmStatusBadge()}catch{}},5000);
setInterval(()=>{if(document.visibilityState==='visible')loadDashboard()},30000);setInterval(()=>{if(document.visibilityState==='visible')loadResources()},10000);

// ═══════════════════════════════════════════════════════════════════
// STAGE 2 BATCH 2 — All UI fixes + new features
// ═══════════════════════════════════════════════════════════════════

// ── Global modal helper ─────────────────────────────────────────────
function showInfoModal(title, html){
  let m=$('infoModal');
  if(!m){m=document.createElement('div');m.id='infoModal';m.className='detail-modal';
    m.innerHTML='<div class="modal-panel"><button class="close-btn" onclick="document.getElementById(\'infoModal\').style.display=\'none\'">✕</button><div id="infoModalContent"></div></div>';
    document.body.appendChild(m);
    m.addEventListener('click',e=>{if(e.target===m)m.style.display='none'});
  }
  $('infoModalContent').innerHTML=`<h2>${esc(title)}</h2>${html}`;
  m.style.display='flex';
}

// ── Fix: prettify any JSON result box (replaces raw JSON) ─────────────
function prettyResult(data, status){
  if(status==='running'||status==='RUNNING')
    return `<div class="result-status running-badge">⏳ RUNNING…</div>`;
  if(status==='error'||status==='ERROR')
    return `<div class="result-status error-badge">✗ ERROR</div>`;
  if(typeof data==='string') return `<div class="result-pretty">${esc(data)}</div>`;
  if(!data) return '';
  const lines=[];
  function walk(obj,depth=0){
    if(typeof obj!=='object'||obj===null){lines.push(`<span class="pv">${esc(String(obj))}</span>`);return}
    if(Array.isArray(obj)){
      if(obj.length===0){lines.push('<span class="pv">—</span>');return}
      obj.forEach((v,i)=>{lines.push(`<div class="pr pl${depth}"><span class="pk">[${i}]</span> `);walk(v,depth+1);lines.push('</div>')});return}
    Object.entries(obj).forEach(([k,v])=>{
      if(k==='raw_xml'||k==='stdout'||k==='stderr'||k==='raw_output') return;
      lines.push(`<div class="pr pl${depth}"><span class="pk">${esc(k)}</span> `);
      if(typeof v==='object'&&v!==null){lines.push('<br>');walk(v,depth+1)}
      else lines.push(`<span class="pv">${esc(String(v))}</span>`);
      lines.push('</div>');
    });
  }
  walk(data);
  const badge=status?`<div class="result-status complete-badge">✓ COMPLETE</div>`:'';
  return badge+`<div class="result-pretty-wrap">${lines.join('')}</div>`;
}

// ── Fix shell UI: show formatted result, not raw JSON ──────────────
async function shellRunUI(){
  const command=$('shellCommand').value.trim();
  if(!command)return toast('Masukkan perintah shell');
  const box=$('systemControlResult');
  box.innerHTML=`<div class="result-status running-badge">⏳ RUNNING: ${esc(command)}</div>`;
  try{
    const r=await api('/api/shell',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({command})});
    if(r.ok){
      let html=`<div class="result-status complete-badge">✓ COMPLETE (exit ${r.returncode})</div>`;
      if(r.stdout) html+=`<div class="shell-out"><b>stdout:</b><pre>${esc(r.stdout)}</pre></div>`;
      if(r.stderr) html+=`<div class="shell-err"><b>stderr:</b><pre>${esc(r.stderr)}</pre></div>`;
      box.innerHTML=html;
    }else{box.innerHTML=`<div class="result-status error-badge">✗ ${esc(r.error||'Shell error')}</div>`}
  }catch(e){box.innerHTML=`<div class="result-status error-badge">✗ ${esc(e.message)}</div>`}
}
async function sudoRunUI(){
  if(!confirm('Jalankan dengan sudo? Password Anda diinput langsung ke terminal, tidak dikirim ke ASEP/LLM.'))return;
  const command=$('shellCommand').value.trim();
  if(!command)return toast('Masukkan perintah');
  const box=$('systemControlResult');
  box.innerHTML=`<div class="result-status running-badge">⏳ RUNNING (sudo): ${esc(command)}</div>`;
  try{
    const r=await api('/api/sudo',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({command,approved:true})});
    let html=`<div class="result-status complete-badge">✓ COMPLETE</div>`;
    if(r.stdout) html+=`<div class="shell-out"><pre>${esc(r.stdout)}</pre></div>`;
    if(r.stderr) html+=`<div class="shell-err"><pre>${esc(r.stderr)}</pre></div>`;
    box.innerHTML=html;
  }catch(e){box.innerHTML=`<div class="result-status error-badge">✗ ${esc(e.message)}</div>`}
}

// ── Fix validation result: no raw JSON ────────────────────────────
async function runTargetAction(target, action){
  const box=$('validationResult');
  box.innerHTML=`<div class="result-status running-badge">⏳ RUNNING: ${esc(action)} → ${esc(target)}</div>`;
  try{
    const r=await api('/api/target/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,action})});
    box.innerHTML=prettyResult(r,'complete');
    toast(`${action} selesai`);
    await loadDashboard();
  }catch(e){
    box.innerHTML=`<div class="result-status error-badge">✗ ${esc(e.message)}</div>`;
    toast(e.message);
  }
}

// ── Fix missions page: Recommend Capabilities now shows formatted cards ──
async function recommendMission(){
  const box=$('missionResult');
  box.innerHTML=`<div class="result-status running-badge">⏳ Menganalisis objective dan environment…</div>`;
  try{
    const evidence=$('missionEvidence').value.split('\n').map(x=>x.trim()).filter(Boolean);
    const env=[$('missionTarget').value.trim()].filter(Boolean);
    const objective=$('missionObjective').value.trim();
    if(!objective)return toast('Isi objective terlebih dahulu');
    const r=await api('/api/capabilities/recommend',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({objective,evidence,environment:env})});
    const caps=r.capabilities||[];
    if(!caps.length){box.innerHTML='<div class="empty">Tidak ada capability yang direkomendasikan untuk objective ini.</div>';return}
    box.innerHTML=`<div class="result-status complete-badge">✓ ${caps.length} capability ditemukan</div>`+
      caps.map(c=>`<div class="cap-card step-card">
        <b>${esc(c.name||c.capability||c.id||'Capability')}</b>
        <small class="cap-reason">${esc(c.reason||c.description||'')}</small>
        <button class="secondary" onclick="capabilityAction('${esc(c.id||c.capability||'')}')">Gunakan →</button>
      </div>`).join('');
  }catch(e){box.innerHTML=`<div class="result-status error-badge">✗ ${esc(e.message)}</div>`}
}

// ── Fix: tool/evidence chain output ──────────────────────────────────
async function toolRun(){
  const box=$('toolResult');
  box.innerHTML=`<div class="result-status running-badge">⏳ Menjalankan tool…</div>`;
  try{
    const r=await api('/api/tools/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:$('toolTarget').value.trim(),tool:$('toolTool').value.trim(),profile:$('toolProfile').value.trim()})});
    box.innerHTML=prettyResult(r.result||r,'complete');
  }catch(e){box.innerHTML=`<div class="result-status error-badge">✗ ${esc(e.message)}</div>`}
}
async function evidenceChain(){
  const box=$('toolResult');
  box.innerHTML=`<div class="result-status running-badge">⏳ Menjalankan evidence chain…</div>`;
  try{
    const r=await api('/api/tools/execute-chain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:$('toolTarget').value.trim(),tool:$('toolTool').value.trim(),profile:$('toolProfile').value.trim()})});
    box.innerHTML=prettyResult(r.result||r,'complete');
  }catch(e){box.innerHTML=`<div class="result-status error-badge">✗ ${esc(e.message)}</div>`}
}

// ── Fix adaptive analyze / passive deep dive output ───────────────
async function passiveDeepDiveUI(){
  const box=$('reasonControlResult');
  box.innerHTML=`<div class="result-status running-badge">⏳ Passive deep dive…</div>`;
  try{
    const target=$('reasonTarget').value.trim();
    const obs=JSON.parse($('reasonObservations').value||'[]');
    const r=await api('/api/target-path/passive-deep-dive',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,evidence:obs,relationships:[]})});
    box.innerHTML=prettyResult(r.result||r,'complete');
  }catch(e){box.innerHTML=`<div class="result-status error-badge">✗ ${esc(e.message)}</div>`}
}
async function adaptiveAnalyzeUI(){
  const box=$('reasonControlResult');
  box.innerHTML=`<div class="result-status running-badge">⏳ Adaptive analyze…</div>`;
  try{
    const target=$('reasonTarget').value.trim();
    const obs=JSON.parse($('reasonObservations').value||'[]');
    const r=await api('/api/adaptive/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,observations:obs})});
    box.innerHTML=prettyResult(r.result||r,'complete');
  }catch(e){box.innerHTML=`<div class="result-status error-badge">✗ ${esc(e.message)}</div>`}
}
async function replanUI(){
  const box=$('reasonControlResult');
  box.innerHTML=`<div class="result-status running-badge">⏳ Replanning…</div>`;
  try{
    const objective=$('missionObjective')?.value?.trim()||'';
    const failed_actions=JSON.parse($('replanFailed')?.value||'[]');
    const r=await api('/api/replan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({objective,failed_actions,blocked_paths:[],evidence:[]})});
    box.innerHTML=prettyResult(r,'complete');
  }catch(e){box.innerHTML=`<div class="result-status error-badge">✗ ${esc(e.message)}</div>`}
}

// ── Fix intelligence summary: clickable stat cards ────────────────
async function loadIntelligenceSummary(){
  try{
    const d=await api('/api/v2/intelligence/summary');
    renderIntelSummary(d);
    const ev=await api('/api/v2/evidence');
    const items=(ev.evidence||[]).slice(0,10);
    $('intelEvidenceCount').textContent=ev.evidence?.length||0;
    $('intelEvidence').innerHTML=items.map(e=>`<button class="detail-link" onclick="openEvidenceDetail(${e.id})"><b>#${e.id} ${esc(e.evidence_type)}</b><small>${esc(e.status)} · ${esc(e.target)}</small></button>`).join('')||'<div class="empty small-empty">No evidence stored yet.</div>';
    // Make metrics clickable
    setTimeout(()=>{
      document.querySelectorAll('#intelMetrics .metric').forEach(card=>{
        const label=card.querySelector('small')?.textContent?.trim()||'';
        card.style.cursor='pointer';
        card.onclick=()=>showIntelStatPopup(label,d);
      });
    },100);
  }catch(e){$('intelReadinessState').textContent='ERROR';$('intelNextAction').innerHTML=`<div class="list-item">${esc(e.message)}</div>`}
}

async function showIntelStatPopup(label, summary){
  const lo=label.toLowerCase();
  let title='', content='';
  try{
    if(lo.includes('active host')){
      const r=await api('/api/v2/targets');
      const live=(r.targets||[]).filter(t=>['up','local','reachable'].includes(String(t.state||'').toLowerCase()));
      title=`Active Hosts (${live.length})`;
      content=live.map(t=>`<div class="popup-row"><b>${esc(t.address)}</b><span>${esc(t.hostname||t.name||'—')} · ${esc(t.vendor||'—')} · ${esc(t.state)}</span></div>`).join('')||'<div class="empty">No active hosts</div>';
    } else if(lo.includes('identified')){
      const r=await api('/api/v2/targets');
      const id=(r.targets||[]).filter(t=>t.hostname||t.vendor||t.mac);
      title=`Identified Hosts (${id.length})`;
      content=id.map(t=>`<div class="popup-row"><b>${esc(t.address)}</b><span>${esc(t.hostname||'—')} · MAC: ${esc(t.mac||'—')} · ${esc(t.vendor||'—')}</span></div>`).join('');
    } else if(lo.includes('service')){
      const r=await api('/api/v2/targets');
      const svc=(r.targets||[]).filter(t=>(t.ports||[]).length>0);
      title=`Hosts with Services (${svc.length})`;
      content=svc.map(t=>`<div class="popup-row"><b>${esc(t.address)}</b><span>${(t.ports||[]).slice(0,8).map(p=>`${p.port}/${p.protocol}${p.service?' ('+p.service+')':''}`).join(' · ')}</span></div>`).join('');
    } else if(lo.includes('platform')){
      const r=await api('/api/v2/targets');
      const plat=(r.targets||[]).filter(t=>t.role&&t.role!=='unknown');
      title=`Identified Platforms (${plat.length})`;
      content=plat.map(t=>`<div class="popup-row"><b>${esc(t.address)}</b><span>${esc(t.role)} · ${esc(t.asset_type||'—')}</span></div>`).join('');
    } else if(lo.includes('confirmed')){
      const r=await api('/api/v2/findings');
      const conf=(r.findings||[]).filter(f=>f.status==='Confirmed'||f.status==='validated');
      title=`Confirmed Findings (${conf.length})`;
      content=conf.map(f=>`<div class="popup-row"><b>${esc(f.title||f.finding_type||'Finding')}</b><span>${esc(f.target||'—')} · ${esc(f.severity||'—')}</span></div>`).join('')||'<div class="empty">No confirmed findings yet</div>';
    } else {
      title=label; content=`<div class="popup-row">${esc(JSON.stringify(summary,null,2))}</div>`;
    }
  }catch(e){title=label;content=`<div class="result-status error-badge">✗ ${esc(e.message)}</div>`}
  showInfoModal(title, content);
}

// ── Attack Graph zoom (pinch/wheel + button) ─────────────────────────
(function patchGraphZoom(){
  const orig=window.initGraphPan||function(){};
  window.initGraphPan=function(box){
    if(box.dataset.panBound)return;
    box.dataset.panBound='1';
    let scale=1,minScale=0.3,maxScale=4;
    let dragging=false,moved=false,startX=0,startY=0,startTX=0,startTY=0;
    function getVP(){return box.querySelector('.graph-viewport')}
    function applyTransform(tx,ty,sc){
      const vp=getVP();if(!vp)return;
      const minTX=Math.min(0,box.clientWidth-vp.offsetWidth*sc),minTY=Math.min(0,box.clientHeight-vp.offsetHeight*sc);
      tx=Math.max(minTX,Math.min(0,tx));ty=Math.max(minTY,Math.min(0,ty));
      vp.style.transformOrigin='0 0';
      vp.style.transform=`translate(${tx}px,${ty}px) scale(${sc})`;
      vp._tx=tx;vp._ty=ty;vp._sc=sc||1;
    }
    box.addEventListener('wheel',e=>{
      e.preventDefault();
      const vp=getVP();if(!vp)return;
      const rect=box.getBoundingClientRect();
      const mx=e.clientX-rect.left,my=e.clientY-rect.top;
      const delta=e.deltaY<0?1.15:0.87;
      const newScale=Math.max(minScale,Math.min(maxScale,(vp._sc||1)*delta));
      const ratio=newScale/(vp._sc||1);
      const tx=(vp._tx||0)-(mx-(vp._tx||0))*(ratio-1);
      const ty=(vp._ty||0)-(my-(vp._ty||0))*(ratio-1);
      scale=newScale;applyTransform(tx,ty,scale);
    },{passive:false});
    box.addEventListener('pointerdown',e=>{const vp=getVP();if(!vp)return;dragging=true;moved=false;box.classList.add('panning');startX=e.clientX;startY=e.clientY;startTX=vp._tx||0;startTY=vp._ty||0;try{box.setPointerCapture(e.pointerId)}catch{}});
    box.addEventListener('pointermove',e=>{if(!dragging)return;const dx=e.clientX-startX,dy=e.clientY-startY;if(Math.abs(dx)>4||Math.abs(dy)>4)moved=true;if(!moved)return;applyTransform(startTX+dx,startTY+dy,scale)});
    const end=()=>{if(!dragging)return;dragging=false;box.classList.remove('panning');if(moved){box.dataset.dragging='1';setTimeout(()=>delete box.dataset.dragging,50)}};
    box.addEventListener('pointerup',end);box.addEventListener('pointercancel',end);
    // Zoom controls
    function addZoomControls(){
      if(box.querySelector('.graph-zoom-ctrl'))return;
      const ctrl=document.createElement('div');ctrl.className='graph-zoom-ctrl';
      ctrl.innerHTML=`<button onclick="graphZoom(this,'${box.id}',1.3)" title="Zoom in">＋</button><button onclick="graphZoom(this,'${box.id}',0.77)" title="Zoom out">－</button><button onclick="graphZoom(this,'${box.id}',0)" title="Reset">⤢</button>`;
      box.appendChild(ctrl);
    }
    addZoomControls();
    box._applyTransform=applyTransform;
    box._scale=()=>scale;
  };
  window.graphZoom=function(btn,boxId,factor){
    const box=$(boxId);if(!box)return;
    const vp=box.querySelector('.graph-viewport');if(!vp)return;
    if(factor===0){box._applyTransform&&box._applyTransform(0,0,1);return}
    const cur=vp._sc||1;const ns=Math.max(0.3,Math.min(4,cur*factor));
    const cx=box.clientWidth/2,cy=box.clientHeight/2;
    const tx=(vp._tx||0)-(cx-(vp._tx||0))*(ns/cur-1);
    const ty=(vp._ty||0)-(cy-(vp._ty||0))*(ns/cur-1);
    box._applyTransform&&box._applyTransform(tx,ty,ns);
  };
})();

// ── Attack Paths: node click shows info popup ──────────────────────
(function patchPathsGraph(){
  const origRender=window.renderGraph;
  window.renderGraph=function(data,boxId='attackGraph'){
    origRender&&origRender(data,boxId);
    if(boxId==='pathsGraph'){
      const box=$(boxId);if(!box)return;
      box.querySelectorAll('.graph-node').forEach(n=>{
        n.addEventListener('click',e=>{
          if(box.dataset.dragging==='1'){e.preventDefault();return}
          const label=n.querySelector('b')?.textContent||'';
          const detail=Array.from(n.querySelectorAll('small')).map(s=>s.textContent).join('\n');
          showInfoModal(`Network Node: ${label}`,`<div class="popup-row">${esc(detail||label)}</div>`);
        });
      });
    }
  };
})();

// ── OS Logo in Target Inventory ────────────────────────────────────
function osLogoFromTarget(t){
  const os_det=(t.metadata?.os_detection?.matches||[])[0]?.name||'';
  const role=String(t.role||'').toLowerCase();
  const asset=String(t.asset_type||'').toLowerCase();
  const lo=(os_det+' '+role+' '+asset).toLowerCase();
  if(/windows|microsoft|win32|winnt/.test(lo))
    return `<img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA4OCA4OCI+PHJlY3QgeD0iNCIgeT0iNCIgd2lkdGg9IjM4IiBoZWlnaHQ9IjM4IiBmaWxsPSIjZjM1MDI1Ii8+PHJlY3QgeD0iNDYiIHk9IjQiIHdpZHRoPSIzOCIgaGVpZ2h0PSIzOCIgZmlsbD0iIzgwYmE1YiIvPjxyZWN0IHg9IjQiIHk9IjQ2IiB3aWR0aD0iMzgiIGhlaWdodD0iMzgiIGZpbGw9IiMwMDc4ZDciLz48cmVjdCB4PSI0NiIgeT0iNDYiIHdpZHRoPSIzOCIgaGVpZ2h0PSIzOCIgZmlsbD0iI2ZmYjkwMCIvPjwvc3ZnPg==" class="os-logo" title="${esc(os_det||'Windows')}" alt="Windows">`;
  if(/linux|ubuntu|debian|centos|kali|redhat|arch|alpine|fedora|mint/.test(lo))
    return `<img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA4OCA4OCI+PGVsbGlwc2UgY3g9IjQ0IiBjeT0iNTYiIHJ4PSIyNiIgcnk9IjI0IiBmaWxsPSIjZTZkY2M4IiBzdHJva2U9IiMzMzMiIHN0cm9rZS13aWR0aD0iMiIvPjxlbGxpcHNlIGN4PSI0NCIgY3k9IjMyIiByeD0iMTgiIHJ5PSIyMiIgZmlsbD0iI2U2ZGNjOCIgc3Ryb2tlPSIjMzMzIiBzdHJva2Utd2lkdGg9IjIiLz48ZWxsaXBzZSBjeD0iMzAiIGN5PSIyMiIgcng9IjEwIiByeT0iMTQiIGZpbGw9IiNlNmRjYzgiIHN0cm9rZT0iIzMzMyIgc3Ryb2tlLXdpZHRoPSIyIi8+PGVsbGlwc2UgY3g9IjU4IiBjeT0iMjIiIHJ4PSIxMCIgcnk9IjE0IiBmaWxsPSIjZTZkY2M4IiBzdHJva2U9IiMzMzMiIHN0cm9rZS13aWR0aD0iMiIvPjxjaXJjbGUgY3g9IjM3IiBjeT0iMjgiIHI9IjQiIGZpbGw9IiMzMzMiLz48Y2lyY2xlIGN4PSI1MSIgY3k9IjI4IiByPSI0IiBmaWxsPSIjMzMzIi8+PGVsbGlwc2UgY3g9IjM2IiBjeT0iNjYiIHJ4PSI3IiByeT0iMTIiIGZpbGw9IiNlNmRjYzgiIHN0cm9rZT0iIzMzMyIgc3Ryb2tlLXdpZHRoPSIyIiB0cmFuc2Zvcm09InJvdGF0ZSgtMTAgMzYgNjYpIi8+PGVsbGlwc2UgY3g9IjUyIiBjeT0iNjYiIHJ4PSI3IiByeT0iMTIiIGZpbGw9IiNlNmRjYzgiIHN0cm9rZT0iIzMzMyIgc3Ryb2tlLXdpZHRoPSIyIiB0cmFuc2Zvcm09InJvdGF0ZSgxMCA1MiA2NikiLz48L3N2Zz4=" class="os-logo" title="${esc(os_det||'Linux')}" alt="Linux">`;
  return '';
}

// Patch loadTargets to add OS logos ─────────────────────────────────
(function patchLoadTargets(){
  const orig=window.loadTargets;
  window.loadTargets=async function(){
    try{
      const r=await api('/api/v2/targets');
      const box=$('targetsList');
      if(!r.targets?.length){box.innerHTML='<div class="empty large">No active-host inventory yet.</div>';await loadEnvironment();return}
      box.innerHTML=r.targets.map(t=>{
        const md=t.metadata||{};
        const hostname=md.hostname||t.name||'Hostname not resolved';
        const vendor=t.vendor||md.identity?.vendor||'Manufacturer not resolved';
        const mac=t.mac||md.identity?.mac_normalized||'MAC unavailable';
        const ports=Array.isArray(t.ports)?t.ports:[];
        const identified=ports.filter(p=>String(p.state||'').toLowerCase()==='open'||p.service);
        const portText=identified.length?identified.map(p=>`${p.port}/${p.protocol||'tcp'}`).join(' · '):'No identified ports';
        const msfReady=identified.some(p=>p.service||p.product||p.version);
        const osLogo=osLogoFromTarget(t);
        const deviceLine=t.asset_brand?`<small><strong>Device:</strong> ${esc(t.asset_type||'—')} · ${esc(t.asset_brand)}${t.asset_confidence?` (${esc(t.asset_confidence)} confidence)`:''}</small>`:'';
        const readyBadge=t.autonomous_ready?'<span class="auto-attack-ready" title="Cukup informasi untuk serangan autonomous">⚡ ATTACK READY</span>':'';
        return `<div class="target-card"><div class="target-title"><button class="detail-link target-main-link" onclick="targetDetails('${esc(t.address)}')"><b>${esc(t.address)}</b>${osLogo}${readyBadge}</button><div class="target-badges">${deepScanFailedHosts[t.address]?`<span class="deep-scan-badge deep-scan-failed" title="${esc(deepScanFailedHosts[t.address])}">⚠ DEEP SCAN FAILED</span>`:(t.deep_scanned?'<span class="deep-scan-badge">DEEP SCAN ✓</span>':'')}<span class="status">${esc(t.scope_status||t.scope||'UNKNOWN')}</span></div></div><small><strong>Hostname:</strong> ${esc(hostname)} · <strong>Manufacturer:</strong> ${esc(vendor)}</small>${deviceLine}<small><strong>MAC:</strong> ${esc(mac)}</small><small><strong>IDENTIFIED PORTS:</strong> ${esc(portText)}</small><small>${esc(t.role)} · ${esc(t.state)} · ${t.services} services · ${t.evidence} evidence · ${t.findings} findings</small>${msfReady?`<div class="button-row"><button class="secondary msf-action" onclick="event.stopPropagation();openMetasploitForTarget('${esc(t.address)}')">● METASPLOIT</button><button class="secondary" onclick="event.stopPropagation();loadExploitCandidates('${esc(t.address)}')">🔎 CEK KANDIDAT EXPLOIT</button></div><div id="exploitBox-${esc(t.address)}" class="exploit-candidates-box" onclick="event.stopPropagation()"></div>`:''}</div>`;
      }).join('');
      await loadEnvironment();
    }catch(e){toast(e.message)}
  };
})();

// ── Autonomous Attack Target Menu ─────────────────────────────────
async function loadAutonomousTargets(){
  const box=$('autonomousTargetList');if(!box)return;
  box.innerHTML='<div class="empty">⏳ Menganalisis target…</div>';
  try{
    const r=await api('/api/v2/targets');
    const targets=(r.targets||[]);
    const ready=targets.filter(t=>{
      const ports=Array.isArray(t.ports)?t.ports:[];
      const hasSvc=ports.some(p=>p.service||p.product||p.version);
      const hasEvidence=(t.evidence||0)>=2;
      const hasDeepScan=!!t.deep_scanned;
      return hasSvc&&hasEvidence&&hasDeepScan;
    });
    if(!ready.length){box.innerHTML='<div class="empty">Belum ada target dengan informasi yang cukup untuk serangan autonomous. Jalankan Deep Scan pada target terlebih dahulu.</div>';return}
    box.innerHTML=ready.map((t,i)=>{
      const ports=(t.ports||[]).filter(p=>p.service||p.product||p.version);
      return `<div class="auto-target-card" id="auto-target-${i}">
        <div class="auto-target-head">
          <b>${esc(t.address)}</b>${osLogoFromTarget(t)}
          <span class="auto-ready-badge">⚡ ATTACK READY</span>
        </div>
        <small>${esc(t.hostname||t.name||'—')} · ${esc(t.vendor||'—')} · ${ports.length} services identified</small>
        <div class="auto-workflow">
          <div class="workflow-step" id="ws-${i}-1">
            <span class="step-num">1</span>
            <span>Konfirmasi scope & otorisasi</span>
            <button class="secondary" onclick="autoWorkflowStep(${i},'${esc(t.address)}',1)">Konfirmasi</button>
          </div>
          <div class="workflow-step locked" id="ws-${i}-2">
            <span class="step-num">2</span>
            <span>Cari kandidat exploit (Metasploit + ExploitDB)</span>
            <button class="secondary" onclick="autoWorkflowStep(${i},'${esc(t.address)}',2)" disabled>Cari Exploit</button>
          </div>
          <div class="workflow-step locked" id="ws-${i}-3">
            <span class="step-num">3</span>
            <span>Validasi prerequisite & pilih exploit terbaik</span>
            <button class="secondary" onclick="autoWorkflowStep(${i},'${esc(t.address)}',3)" disabled>Validate</button>
          </div>
          <div class="workflow-step locked" id="ws-${i}-4">
            <span class="step-num">4</span>
            <span>CHECK (approval required sebelum RUN)</span>
            <button class="secondary" onclick="autoWorkflowStep(${i},'${esc(t.address)}',4)" disabled>CHECK</button>
          </div>
          <div class="workflow-step locked" id="ws-${i}-5">
            <span class="step-num">5</span>
            <span>RUN exploit (operator approval)</span>
            <button class="secondary msf-action" onclick="autoWorkflowStep(${i},'${esc(t.address)}',5)" disabled>🚀 RUN</button>
          </div>
          <div class="workflow-step locked" id="ws-${i}-6">
            <span class="step-num">6</span>
            <span>Session → Post-exploitation intelligence</span>
            <button class="secondary" onclick="autoWorkflowStep(${i},'${esc(t.address)}',6)" disabled>Analyze Session</button>
          </div>
        </div>
        <div class="auto-result" id="auto-result-${i}"></div>
      </div>`;
    }).join('');
  }catch(e){box.innerHTML=`<div class="empty">✗ ${esc(e.message)}</div>`}
}

const _autoWorkflowState={};
async function autoWorkflowStep(idx,target,step){
  const key=`${idx}-${target}`;
  _autoWorkflowState[key]=_autoWorkflowState[key]||{};
  const state=_autoWorkflowState[key];
  const resultBox=$(`auto-result-${idx}`);
  const markComplete=(s)=>{
    const ws=$(`ws-${idx}-${s}`);if(ws){ws.classList.remove('locked');ws.classList.add('done');ws.querySelector('button').textContent='✓ Done'}
    const next=$(`ws-${idx}-${s+1}`);if(next){next.classList.remove('locked');const btn=next.querySelector('button');if(btn)btn.disabled=false}
  };
  if(step===1){
    if(!confirm(`Konfirmasi target ${target} dalam scope dan Anda memiliki otorisasi untuk pengujian?\n\nLanjutkan HANYA jika ada izin tertulis.`))return;
    resultBox.innerHTML='<div class="result-status complete-badge">✓ Scope & otorisasi dikonfirmasi operator</div>';
    markComplete(1); state.authorized=true;
  } else if(step===2){
    if(!state.authorized)return toast('Selesaikan step 1 dahulu');
    resultBox.innerHTML='<div class="result-status running-badge">⏳ Mencari kandidat exploit…</div>';
    try{
      const r=await api(`/api/v2/targets/${encodeURIComponent(target)}/exploit-candidates`);
      const svcs=r.services||[];
      const hasCandidate=svcs.some(s=>(s.local_msf||[]).length||(s.internet_cve||[]).length);
      state.candidates=svcs;
      resultBox.innerHTML=`<div class="result-status complete-badge">✓ ${svcs.length} service dicek, ${svcs.filter(s=>s.local_msf?.length).length} dengan kandidat MSF, ${svcs.filter(s=>s.internet_cve?.length).length} dengan referensi CVE</div>`;
      if(!hasCandidate){resultBox.innerHTML+='<div class="auto-note">⚠ Tidak ada kandidat exploit ditemukan. Lanjutkan untuk manual analysis.</div>'}
      markComplete(2);
    }catch(e){resultBox.innerHTML=`<div class="result-status error-badge">✗ ${esc(e.message)}</div>`}
  } else if(step===3){
    const svcs=state.candidates||[];
    const msfCandidates=svcs.flatMap(s=>(s.local_msf||[]).map(m=>({module:m.module,service:s.service,port:s.port,query:s.query_used})));
    state.selectedModule=msfCandidates[0]?.module||null;
    resultBox.innerHTML=msfCandidates.length
      ?`<div class="result-status complete-badge">✓ Kandidat terbaik: <b>${esc(state.selectedModule)}</b></div>`+msfCandidates.map(m=>`<div class="popup-row"><b>${esc(m.module)}</b><small>${esc(m.service)} port ${esc(String(m.port||'?'))}</small></div>`).join('')
      :'<div class="auto-note">⚠ Tidak ada modul MSF lokal. Analisis manual diperlukan.</div>';
    markComplete(3);
  } else if(step===4){
    if(!state.selectedModule){resultBox.innerHTML+='<div class="auto-note">⚠ Tidak ada modul terpilih — CHECK tidak tersedia. Lanjut manual.</div>';markComplete(4);return}
    resultBox.innerHTML=`<div class="result-status running-badge">⏳ CHECK: ${esc(state.selectedModule)} → ${esc(target)}</div>`;
    showView('exploitation');toast('Buka Metasploit → CHECK modul yang dipilih');
    markComplete(4);
  } else if(step===5){
    if(!confirm(`RUN exploit ke ${target}?\n\nModul: ${state.selectedModule||'(manual)'}\n\nIni akan mencoba eksekusi exploit. Pastikan otorisasi sudah ada.`))return;
    resultBox.innerHTML='<div class="auto-note">⚡ RUN dimulai → pantau di halaman Exploitation & Sessions</div>';
    showView('exploitation');
    markComplete(5);
  } else if(step===6){
    resultBox.innerHTML='<div class="result-status running-badge">⏳ Menganalisis sessions…</div>';
    try{
      const r=await api('/api/v2/sessions');
      const sessions=r.sessions||[];
      const relevant=sessions.filter(s=>s.target===target);
      if(relevant.length){
        resultBox.innerHTML=`<div class="result-status complete-badge">✓ SESSION AKTIF pada ${esc(target)}</div>`+
          relevant.map(s=>`<div class="popup-row"><b>Session ${esc(String(s.id||''))}</b><span>${esc(s.target)} · ${esc(s.status||'active')}</span></div>`).join('');
      }else{resultBox.innerHTML='<div class="auto-note">Belum ada session aktif pada target ini. Coba jalankan exploit manual terlebih dahulu.</div>'}
    }catch(e){resultBox.innerHTML=`<div class="result-status error-badge">✗ ${esc(e.message)}</div>`}
    markComplete(6);
  }
}

// ── Realtime activity ticker ──────────────────────────────────────
async function tickActivity(){
  try{
    const r=await api('/api/status');
    const ticker=$('activityTicker');
    if(!ticker)return;
    const activity=r.current_activity||'';
    const active=r.active!==false;
    if(activity&&active){ticker.textContent=`⏳ ${activity}`;ticker.className='activity-ticker running'}
    else{ticker.textContent=r.version?`ASEP v${r.version} · READY`:'READY';ticker.className='activity-ticker ready'}
  }catch{}
}
setInterval(tickActivity,3000);
tickActivity();
