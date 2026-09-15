const state={tasks:new Map(),sources:new Map()};
let selectedFiles=[];
let cveTotal=0,fileRevision=0,countingFiles=false;
const active=status=>["queued","running","stopping"].includes(status);
const $=s=>document.querySelector(s);
const labels={queued:'排队中',running:'运行中',completed:'已完成',success:'成功',failed:'失败',interrupted:'已中断',stopping:'终止中',cancelled:'已终止'};
const escapeHtml=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
async function renderFiles(files){
  const revision=++fileRevision; countingFiles=true; $('#task-form button[type=submit]').disabled=true;
  const names=files.map(file=>file.webkitRelativePath||file.name);
  $('#file-list').textContent=files.length?`${files.length} 个文件：${names.slice(0,3).join('、')}${files.length>3?'…':''}`:'尚未选择文件';
  try {
    const ids=new Set();
    for(const file of files){
      const text=`${file.webkitRelativePath||file.name}\n${await file.text()}`;
      for(const id of text.match(/CVE-\d{4}-\d{4,}/gi)||[])ids.add(id.toUpperCase());
    }
    if(revision!==fileRevision)return;
    cveTotal=ids.size;
    $('#file-list').textContent+=` · ${cveTotal} 条去重 CVE`;
    syncRanges();
  } catch(error) {
    if(revision===fileRevision){cveTotal=0;syncRanges();$('#file-list').textContent=`读取失败：${error.message}`;}
  } finally {
    if(revision===fileRevision){countingFiles=false;$('#task-form button[type=submit]').disabled=false;}
  }

}
function modeLabel(mode){return mode==='full'?'完整流程':mode==='poc'?'仅生成 PoC':mode==='analysis'?'仅分析':'仅环境'}
function taskCard(task){
  const done=task.completed||0,total=task.total||1;
  const items=Object.values(task.items||{}).map(item=>`<div class="item ${escapeHtml(item.status||'')}"><div class="item-row"><span class="item-cve">${escapeHtml(item.cve_id)}</span><span class="item-phase">${escapeHtml(labels[item.status]==='终止中'?'终止中':item.phase_label||labels[item.status]||item.phase||'等待')}</span>${['queued','running'].includes(item.status)?`<button type="button" class="secondary" data-cancel-task="${escapeHtml(task.id)}" data-cancel-cve="${escapeHtml(item.cve_id)}">终止</button>`:''}</div><div class="item-msg">${escapeHtml(item.message||'')}</div></div>`).join('');
  const statusClass=escapeHtml(task.status||'');
  return `<article class="task"><div class="task-head"><div><div class="task-name">任务 ${escapeHtml(task.id)}</div><div class="task-meta">${modeLabel(task.mode)} · ${escapeHtml(task.concurrency)} 线程 · ${task.docker_enabled?'Docker 开启':'Docker 关闭'} · ${escapeHtml(task.target_ip||'默认目标')} · ${task.local_only?'本地资料':'允许联网'}</div></div><span class="task-status ${statusClass}">${escapeHtml(labels[task.status]||task.status)}</span>${["queued","running"].includes(task.status)?`<button type="button" class="secondary" data-cancel-task="${escapeHtml(task.id)}">终止任务</button>`:""}</div><div class="task-bar"><i style="width:${Math.round(done/total*100)}%"></i></div><div class="task-meta">${done}/${total} 个 CVE 已结束 · ${escapeHtml(task.selection?.selected_total||task.total)} 条已选</div><div class="task-items">${items}</div></article>`;
}
function render(){
  const list=$('#task-list'); const all=[...state.tasks.values()].sort((a,b)=>String(b.created_at).localeCompare(String(a.created_at)));
  list.innerHTML=all.filter(task=>active(task.status)).map(taskCard).join('');
  $('#empty-state').style.display=all.some(task=>active(task.status))?'none':'flex';
  const history=$('#history-list');
  history.innerHTML=all.filter(task=>!active(task.status)).slice(0,5).map(task=>`<div class="history-row"><div><b>${escapeHtml(task.id)}</b><span>${modeLabel(task.mode)} · ${escapeHtml(task.total)} 条</span></div><div><span class="task-status ${escapeHtml(task.status||'')}">${escapeHtml(labels[task.status]||task.status)}</span><small>${escapeHtml(String(task.created_at||'').replace('T',' ').slice(0,16))}</small></div></div>`).join('')||'<div class="history-empty">暂无历史任务</div>';
  let running=all.filter(task=>task.status==='running').length; $('#task-count').textContent=all.length; $('#running-count').textContent=running;
}
async function loadTasks(){try{const res=await fetch('/api/tasks'); const tasks=await res.json(); tasks.forEach(t=>state.tasks.set(t.id,t)); render(); tasks.filter(t=>active(t.status)).forEach(connect)}catch(e){$('#health-text').textContent='服务不可用'; $('#health-dot').style.background='#b94a4a'}}
function connect(task){if(state.sources.has(task.id))return; const source=new EventSource(`/api/tasks/${task.id}/events`); state.sources.set(task.id,source); source.onmessage=e=>{const event=JSON.parse(e.data); if(event.task)state.tasks.set(task.id,event.task); if(event.event==='item'){const t=state.tasks.get(task.id); if(t&&t.items[event.cve_id])Object.assign(t.items[event.cve_id],event)} if(event.event==='progress'){const t=state.tasks.get(task.id); if(t)t.completed=event.completed} if(event.event==='status'){const t=state.tasks.get(task.id); if(t)t.status=event.status} render(); if(!active(state.tasks.get(task.id)?.status)){source.close();state.sources.delete(task.id)}}; source.onerror=()=>{source.close();state.sources.delete(task.id)} }
$('#file-input').addEventListener('change',e=>{selectedFiles=[...e.target.files];renderFiles(selectedFiles)});
['dragenter','dragover'].forEach(name=>$('#dropzone').addEventListener(name,e=>{e.preventDefault();$('#dropzone').classList.add('drag')}));
['dragleave','drop'].forEach(name=>$('#dropzone').addEventListener(name,e=>{e.preventDefault();$('#dropzone').classList.remove('drag')}));
$('#dropzone').addEventListener('drop',e=>{selectedFiles=[...e.dataTransfer.files];renderFiles(selectedFiles)});
const rangeMode=$('#range-mode'),rangeCount=$('#range-count'),rangeValue=$('#range-count-value');
function updateRangeControls(){
  $('#range-count-row').hidden=!['head','tail'].includes(rangeMode.value);
  $('#range-slice-row').hidden=rangeMode.value!=='slice';
  const count=rangeMode.value==='all'?cveTotal:rangeMode.value==='slice'?Number($('#range-end').value)-Number($('#range-start').value)+1:Number(rangeCount.value);
  $('#range-hint').textContent=`共 ${cveTotal} 条去重 CVE，已选 ${cveTotal?count:0} 条；M/N 按 1 起始，含首尾。`;
}
function syncRanges(changed=''){
  const max=Math.max(1,cveTotal),clamp=v=>Math.max(1,Math.min(max,Math.trunc(Number(v)||1)));
  const pairs=[['range-count','range-count-value'],['range-start-slider','range-start'],['range-end-slider','range-end']];
  for(const [slider,number] of pairs){
    const a=$('#'+slider),b=$('#'+number);
    a.max=b.max=max; a.disabled=b.disabled=!cveTotal;
    a.value=b.value=clamp(changed===slider?a.value:b.value);
  }
  const start=$('#range-start'),end=$('#range-end');
  if(Number(start.value)>Number(end.value)){
    if(changed.startsWith('range-end'))start.value=end.value;
    else end.value=start.value;
  }
  $('#range-start-slider').value=start.value;$('#range-end-slider').value=end.value;
  updateRangeControls();
}
rangeMode.addEventListener('change',updateRangeControls);
for(const id of ['range-count','range-count-value','range-start','range-end','range-start-slider','range-end-slider'])$('#'+id).addEventListener('input',()=>syncRanges(id));
syncRanges();
function updateOptions(){
  const local=$('#local-only').checked,environment=document.querySelector('input[name=mode]:checked').value==='environment';
  const discovery=$('#environment-discovery'),docker=$('#docker-enabled');
  if(local)discovery.checked=false;else if(environment)discovery.checked=true;
  discovery.disabled=local||environment;
  docker.disabled=local||!discovery.checked;if(docker.disabled)docker.checked=false;
}
for(const id of ['local-only','environment-discovery'])$('#'+id).addEventListener('change',updateOptions);
document.querySelectorAll('input[name=mode]').forEach(input=>input.addEventListener('change',updateOptions));
updateOptions();
$('#task-list').addEventListener('click',async event=>{
  const button=event.target.closest('[data-cancel-task]');if(!button)return;
  button.disabled=true;
  const id=button.dataset.cancelTask,cve=button.dataset.cancelCve;
  try{
    const response=await fetch(`/api/tasks/${encodeURIComponent(id)}${cve?`/items/${encodeURIComponent(cve)}`:''}/cancel`,{method:'POST'});
    const task=await response.json();if(!response.ok)throw new Error(task.detail||'终止失败');
    state.tasks.set(id,task);render();
  }catch(error){alert(error.message);button.disabled=false;}
});

document.querySelectorAll('.mode-card input').forEach(input=>input.addEventListener('change',()=>{document.querySelectorAll('.mode-card').forEach(card=>card.classList.toggle('active',card.querySelector('input').checked))}));
$('#task-form').addEventListener('submit',async e=>{e.preventDefault(); const files=selectedFiles.slice(); if(countingFiles)return; if(!files.length){alert('请先选择文件或文件夹');return} const form=new FormData(); files.forEach(file=>form.append('files',file,file.webkitRelativePath||file.name)); form.append('mode',document.querySelector('input[name=mode]:checked').value); form.append('concurrency',$('#concurrency').value); form.append('docker_enabled',$('#docker-enabled').checked?'true':'false'); form.append('target_ip',$('#target-ip').value.trim()); form.append('local_only',String($('#local-only').checked)); form.append('environment_discovery',String($('#environment-discovery').checked)); form.append('output_dir',$('#output-dir').value.trim()); form.append('range_mode',rangeMode.value); form.append('range_count',rangeCount.value); form.append('range_start',$('#range-start').value); form.append('range_end',$('#range-end').value); const button=e.target.querySelector('button'); button.disabled=true; button.textContent='创建中…'; try{const res=await fetch('/api/tasks',{method:'POST',body:form}); const task=await res.json(); if(!res.ok)throw new Error(task.detail||'创建失败'); state.tasks.set(task.id,task); render(); connect(task); e.target.reset(); updateOptions(); document.querySelectorAll('.mode-card').forEach(card=>card.classList.toggle('active',card.querySelector('input').checked)); selectedFiles=[]; renderFiles([]);rangeMode.value='all';updateRangeControls()}catch(err){alert(err.message)}finally{button.disabled=false;button.innerHTML='<span>▶</span> 创建并运行任务'}});
fetch('/api/health').then(r=>r.json()).then(data=>{$('#target-ip').placeholder=data.target_ip||'服务端默认目标';$('#health-dot').style.background='#70c7a4';$('#health-text').textContent=`在线 · ${data.docker_default?'Docker 默认开启':'Docker 默认关闭'}`}).catch(()=>{}); loadTasks();

function kbCard(title, value, detail, tone=''){
  return `<div class="knowledge-card ${tone}"><div class="knowledge-card-title">${escapeHtml(title)}</div><b>${escapeHtml(value)}</b><small>${escapeHtml(detail)}</small></div>`;
}
function renderKnowledge(snapshot){
  const poc=snapshot.poc||{}, custom=snapshot.custom_poc||{}, nvd=snapshot.nvd||{}, pcap=snapshot.pcap||{};
  const years=(nvd.years_available||[]).join(', ')||'暂无';
  $('#knowledge-cards').innerHTML=[
    kbCard('本地 PoC 知识库', `${poc.truncated?'≥':''}${poc.files||0} 个文件`, `${poc.size_mb||0} MB · ${poc.path||''}`),
    kbCard('自定义 PoC', `${custom.files||0} 个文件`, `${custom.size_mb||0} MB · 可直接优先命中`, 'accent'),
    kbCard('NVD 本地 Feed', `${nvd.total_size_mb||0} MB`, `年份：${years}`, nvd.exists?'accent':'warning'),
    kbCard('PCAP 证据库', `${pcap.files||0} 个文件`, `${pcap.size_mb||0} MB · ${pcap.path||''}`),
  ].join('');
}
async function loadKnowledge(query=''){
  try{
    const response=await fetch(`/api/knowledge-bases${query?`?query=${encodeURIComponent(query)}`:''}`);
    const data=await response.json();
    if(!response.ok) throw new Error(data.detail||'读取失败');
    renderKnowledge(data.snapshot||{});
    const matches=data.snapshot?.search?.matches||[];
    $('#knowledge-results').innerHTML=matches.length?matches.map(item=>`<div class="knowledge-result"><b>${escapeHtml(item.name)}</b><small>${escapeHtml(item.path)} · ${Math.round((item.size||0)/1024)} KB</small></div>`).join(''):(query?'<div class="history-empty">没有匹配文件</div>':'');
  }catch(error){$('#knowledge-cards').innerHTML=`<div class="knowledge-loading">知识库状态读取失败：${escapeHtml(error.message)}</div>`;}
}
async function pollNvdJob(jobId){
  const status=$('#nvd-job-status');
  const timer=setInterval(async()=>{
    try{
      const response=await fetch(`/api/knowledge-bases/nvd/jobs/${jobId}`); const job=await response.json();
      if(!response.ok) throw new Error(job.detail||'任务读取失败');
      const current=job.current?` · ${job.current.label}: ${job.current.status}`:'';
      const history=Object.entries(job.year_status||{}).map(([year,entry])=>`${year}: ${entry.status}${entry.status==='error'?` (${entry.message})`:''}`).join('\n');
      status.style.whiteSpace='pre-wrap';
      status.textContent=`计划年份：${(job.years||[]).join(', ')}\n${job.status}${current}\n${history}`;
      if(job.status==='completed'||job.status==='failed'){
        clearInterval(timer); $('#nvd-update').disabled=false; loadKnowledge();
        if(job.status==='failed') status.textContent=`下载失败：${job.error||'未知错误'}`;
        else {
          const result=job.result||{}, errors=result.errors||[];
          const summary=`更新完成：下载 ${result.downloaded?.length||0}，跳过 ${result.skipped?.length||0}`;
          status.textContent=errors.length
            ? `${summary}，失败 ${errors.length}：${errors[0].label||''} ${errors[0].error||'未知错误'}`
            : summary;
          status.textContent+=`\n${history}`;
        }
      }
    }catch(error){clearInterval(timer);$('#nvd-update').disabled=false;status.textContent=`状态读取失败：${error.message}`;}
  },1000);
}
$('#knowledge-refresh').addEventListener('click',()=>loadKnowledge());
$('#knowledge-search-button').addEventListener('click',()=>loadKnowledge($('#knowledge-search').value.trim()));
$('#knowledge-search').addEventListener('keydown',event=>{if(event.key==='Enter')loadKnowledge(event.target.value.trim())});
$('#nvd-years-all').addEventListener('click',()=>{$('#nvd-years').value='all'});
$('#nvd-years-recent').addEventListener('click',()=>{const year=new Date().getFullYear();$('#nvd-years').value=`${year-2}-${year}`});
$('#nvd-update').addEventListener('click',async()=>{
  const button=$('#nvd-update'),status=$('#nvd-job-status'); button.disabled=true; status.textContent='正在创建下载任务…';
  const form=new FormData(); form.append('years',$('#nvd-years').value.trim()); form.append('include_modified',$('#nvd-modified').checked?'true':'false'); form.append('force',$('#nvd-force').checked?'true':'false');
  try{const response=await fetch('/api/knowledge-bases/nvd/update',{method:'POST',body:form}); const job=await response.json(); if(!response.ok)throw new Error(job.detail||'创建失败'); pollNvdJob(job.id)}catch(error){button.disabled=false;status.textContent=`创建失败：${error.message}`;}
});
loadKnowledge();
