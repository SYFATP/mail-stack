const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const script=fs.readFileSync(path.join(__dirname,'../frontend/index.html'),'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const nodes=new Map(),timers=new Map(),requests=[],jobs=new Map();
let timerId=0,jobId=0,failRead=false,deferredRead=null,postStatus='queued';
const domain=name=>({domain:name,enabled:false,dns_provider:'manual',dns_checks:{},receive_ready:false,send_ready:false});
let domains=[domain('sender.example.test')];
function node(id){
 if(!nodes.has(id))nodes.set(id,{innerHTML:'',textContent:'',value:'',checked:false,disabled:false,dataset:{},
  style:{},classList:{toggle(){}},append(){},focus(){},isConnected:true});
 return nodes.get(id);
}
const document={body:{classList:{toggle(){}}},activeElement:null,
 querySelector:id=>id==='#domain-dialog-bg'&&!node('#modal-root').innerHTML?null:node(id),
 querySelectorAll:()=>[],createElement:()=>({style:{},remove(){}})};
const context=vm.createContext({document,console,URL,URLSearchParams,
 localStorage:{getItem:()=>null,removeItem(){}},
 crypto:{randomUUID:()=> 'fixture-'+requests.length},
 setTimeout:(fn,ms)=>{timers.set(++timerId,{fn,ms});return timerId},clearTimeout:id=>timers.delete(id),
 setInterval:()=>1,clearInterval(){},
 fetch:async(url,opt={})=>{
  requests.push({url,opt});const u=new URL(url,'https://fixture.test');let data={};
  if(opt.method==='POST'&&u.pathname.endsWith('/dns-preview')){
   data={id:'preview-'+requests.length,domain:decodeURIComponent(u.pathname.split('/mail-domains/')[1].split('/')[0]),executable:true,actions:[],conflicts:[]};
  }else if(opt.method==='POST'){
   const kind=u.pathname.endsWith('/dns-apply')?'dns_apply':u.pathname.endsWith('/dns-validate')?'dns_validate':'claim';
   data={id:'tracked-'+(++jobId),kind,scope:'source-fixture',status:postStatus};
   jobs.set(data.id,{...data});
  }else if(u.pathname.includes('/domain-jobs/')){
   if(deferredRead)await deferredRead;
   if(failRead){failRead=false;return {ok:false,status:502,json:async()=>({detail:'fixture read interrupted'})}}
   data={...jobs.get(u.pathname.split('/').at(-1))};
  }else if(u.pathname.endsWith('/domain-jobs')){
   const counts={};for(const job of jobs.values())counts[job.status]=(counts[job.status]||0)+1;
   data={items:[...jobs.values()].slice(-1),total:jobs.size,status_counts:counts,
    blocked_claim_sources:[...jobs.values()].some(j=>['queued','running','unknown'].includes(j.status))?['source-fixture']:[]};
  }else if(u.pathname.endsWith('/mail-domains'))data=domains.slice();
  else if(u.pathname.endsWith('/domain-sources'))data={items:[{id:'source-fixture',name:'SFREG',source_type:'sfreg_mx',client_id:'fixture',enabled:true}]};
  else if(u.pathname.endsWith('/dns-credentials'))data={items:[]};
  return {ok:true,status:opt.method==='POST'?202:200,json:async()=>data};
 }});
vm.runInContext(script+'\nglobalThis.t={state,controlJob,controlPage,controlJobWatchers,runControlBatch,logout,watchActiveDomainJobs,controlDomainReadBusy,controlDomainActivity,renderControlUnifiedResults};',context);
const t=context.t;t.state.token='fixture-session';t.state.tab='control';
const writes=()=>requests.filter(r=>r.opt.method==='POST').length;
const refreshes=()=>requests.filter(r=>r.url==='/api/v1/mail-domains').length;
async function tick(){
 const timer=[...timers.entries()].find(([,value])=>[1000,2000].includes(value.ms));
 assert.ok(timer,'Expected a scheduled job status poll');timers.delete(timer[0]);await timer[1].fn();
}
(async()=>{
 await t.controlPage();
 t.state.controlDns.query='claimed';t.state.controlDns.provider='manual';
 let completions=0;
 const job=await t.controlJob('/domain-sources/source-fixture/claim',{count:1,status:'registered',sync_provider:'none'},
  {onComplete:latest=>{completions++;assert.equal(latest.status,'succeeded')}});
 await t.controlPage();
 assert.doesNotMatch(node('#control-dns-body').innerHTML,/claimed.test/,'The enqueue ACK precedes the import');
 const before=refreshes();jobs.get(job.id).status='running';await tick();
 assert.equal(refreshes(),before,'Keep polling without rebuilding the page while a job runs');
 node('#modal-root').innerHTML='A newer DNS dialog';
 domains.push(domain('claimed.test'));jobs.get(job.id).status='succeeded';await tick();
 assert.equal(refreshes(),before+1);assert.match(node('#control-dns-body').innerHTML,/claimed.test/);
 assert.equal(t.state.controlDns.query,'claimed');assert.equal(t.state.controlDns.provider,'manual');
 assert.equal(node('#modal-root').innerHTML,'A newer DNS dialog','Completion must not close a newer modal');
 assert.equal(t.controlJobWatchers.size,0);assert.equal(writes(),1,'Polling must never resubmit an allocation');
 assert.equal(completions,1,'The asynchronous completion callback must run exactly once');

 const retry=await t.controlJob('/domain-sources/source-fixture/claim',{count:1});
 const beforeRetry=refreshes();failRead=true;await tick();
 assert.equal(t.controlJobWatchers.size,1);assert.equal(refreshes(),beforeRetry);assert.equal(writes(),2);
 domains.push(domain('claimed-partial.test'));jobs.get(retry.id).status='partial';await tick();
 assert.match(node('#control-dns-body').innerHTML,/claimed-partial.test/);
 assert.equal(t.controlJobWatchers.size,0);assert.equal(writes(),2);

 const unknown=await t.controlJob('/domain-sources/source-fixture/claim',{count:2});
 jobs.get(unknown.id).status='unknown';await tick();assert.equal(t.controlJobWatchers.size,0);
 assert.equal(writes(),3,'An unknown result must not be retried');

 const left=await t.controlJob('/domain-sources/source-fixture/claim',{count:3});
 t.state.tab='inbox';const unchanged=node('#page').innerHTML,beforeLeave=refreshes();
 jobs.get(left.id).status='succeeded';await tick();
 assert.equal(refreshes(),beforeLeave);assert.equal(node('#page').innerHTML,unchanged);

 t.state.tab='control';
 vm.runInContext('globalThis.batchToasts=[];toast=(text,bad)=>batchToasts.push({text,bad});',context);
 t.state.controlSelection.add('sender.example.test');t.state.controlSelection.add('claimed.test');
 await t.runControlBatch('validate');
 const batchJobs=[...jobs.values()].slice(-2);
 batchJobs[0].status='succeeded';batchJobs[0].result={checks:{mx:{status:'passed'}}};
 await tick();
 assert.doesNotMatch(context.batchToasts.at(-1).text,/完成/,'Wait for every batch job');
 batchJobs[1].status='succeeded';batchJobs[1].result={checks:{dkim:{status:'failed'}}};
 await tick();
 assert.match(context.batchToasts.at(-1).text,/批量DNS 验证完成：成功 1.*检查未通过 1/);
 assert.equal(context.batchToasts.at(-1).bad,true);
 assert.equal(t.state.controlBusyCounts.size,0,'Completion must release both batch rows');
 const doneCount=context.batchToasts.filter(x=>x.text.includes('完成')).length;
 assert.equal(doneCount,1);
 postStatus='succeeded';
 await t.runControlBatch('validate');
 assert.match(context.batchToasts.at(-1).text,/批量DNS 验证完成：成功 2/,'An immediate result must not be overwritten by a submitted toast');
 postStatus='queued';
 // Apply and its server-side validation form one job: hold locks, then refresh
 // and distinguish record-write success from a failed wildcard check.
 for(const d of domains.slice(0,2)){
  d.dns_provider='digitalplat';d.dns_credential_ref='credential-'+d.domain;
  t.state.controlCredentials.push({id:d.dns_credential_ref,provider:'digitalplat',domain:d.domain});
 }
 t.state.controlSelection.clear();domains.slice(0,2).forEach(d=>t.state.controlSelection.add(d.domain));
 const completedBeforeApply=context.batchToasts.filter(x=>x.text.includes('完成')).length;
 await t.runControlBatch('configure');
 const applied=[...jobs.values()].slice(-2),postsAfterApply=writes();
 assert.equal(t.state.controlBusyCounts.size,2);
 applied[0].status='running';applied[0].step='dns_validating';await tick();
 assert.equal(t.state.controlBusyCounts.has(domains[0].domain),true,'Validation must retain the row lock');
 assert.equal(context.batchToasts.filter(x=>x.text.includes('完成')).length,completedBeforeApply);
 applied[0].status='succeeded';applied[0].result={validation_status:'passed',checks:{wildcard_mx:{status:'passed'}}};
 for(let i=0;i<4&&t.state.controlBusyCounts.has(domains[0].domain);i++)await tick();
 assert.equal(t.state.controlBusyCounts.has(domains[0].domain),false);
 assert.equal(t.state.controlBusyCounts.has(domains[1].domain),true);
 applied[1].status='succeeded';applied[1].result={validation_status:'failed',checks:{wildcard_mx:{status:'failed'}}};
 await tick();
 assert.match(context.batchToasts.at(-1).text,/批量DNS 应用与验证完成：成功 1.*检查未通过 1/);
 assert.equal(context.batchToasts.at(-1).bad,true);
 assert.equal(t.state.controlBusyCounts.size,0);
 assert.equal(writes(),postsAfterApply,'Polling the combined job must not repeat DNS writes or enqueue client-side validations');
 const singleApply=await t.controlJob('/mail-domains/sender.example.test/dns-apply',{plan_id:'single-apply'});
 jobs.get(singleApply.id).status='succeeded';
 jobs.get(singleApply.id).result={validation_status:'failed',checks:{wildcard_mx:{status:'failed'}}};
 await tick();
 assert.match(context.batchToasts.at(-1).text,/DNS 已应用，验证仍有未通过项/);
 assert.equal(context.batchToasts.at(-1).bad,true);
 // Read-only completion refreshes readiness but leaves the incident writer held.
 t.state.controlDns.query='';t.state.controlDns.provider='';t.state.controlDns.status='all';
 const name=domains[0].domain;
 const held={id:'held-existing-write',scope:name,kind:'dns_apply',status:'queued',step:'persisted',wait_reason:'incident_hold',wait_until:null};
 jobs.set(held.id,held);t.watchActiveDomainJobs({active_domain_jobs:[held]});
 const read=await t.controlJob('/mail-domains/'+name+'/dns-validate',{}, {notify:false});
 assert.equal(t.state.controlBusyCounts.get(name),2);
 jobs.get(read.id).automatic=true;jobs.get(read.id).status='running';await tick();
 assert.match(t.controlDomainActivity(name),/后台自动验证中.*写入已暂停/);
 Object.assign(domains[0],{enabled:true,receive_ready:true,send_ready:true});
 jobs.get(read.id).status='succeeded';jobs.get(read.id).result={checks:{mx:{status:'passed'}}};
 const beforeReadDone=refreshes();await tick();
 assert.equal(refreshes(),beforeReadDone+1);
 assert.equal(t.state.controlBusyCounts.get(name),1);
 assert.equal(t.controlDomainReadBusy(name),false);
 assert.equal(jobs.get(held.id).status,'queued');
 t.renderControlUnifiedResults();assert.match(node('#control-dns-body').innerHTML,/写入已暂停，等待恢复/);
 let staleCompletion=false;
 await t.controlJob('/domain-sources/source-fixture/claim',{count:4},{onComplete:()=>staleCompletion=true});
 const writesBeforeLogout=writes();
 let release;deferredRead=new Promise(resolve=>release=resolve);
 const pending=tick();const beforeLogout=refreshes();t.logout(false);
 const loginMarkup=node('#app').innerHTML;
 release();await pending;deferredRead=null;
 assert.equal(t.controlJobWatchers.size,0);assert.equal(refreshes(),beforeLogout);
 assert.equal(node('#app').innerHTML,loginMarkup);assert.match(loginMarkup,/登录控制台/);
 assert.equal(staleCompletion,false);assert.equal(writes(),writesBeforeLogout);
 console.log('PASS: queued/running claim completion refreshes DNS list, preserves filters and newer modal, retries reads only, handles partial/unknown, respects navigation and cancels stale polls on logout');
})().catch(error=>{console.error(error);process.exitCode=1});
