const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const script=fs.readFileSync(path.join(__dirname,'../frontend/index.html'),'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const nodes=new Map(),timers=new Map(),requests=[],jobs=new Map();
let timerId=0,clock=100000,failStatus=false,holdStatus=null;
const domains=Array.from({length:200},(_,n)=>({domain:`bulk-${n}.test`,enabled:false,dns_provider:'digitalplat',dns_credential_ref:`cred-${n}`,claim_id:`claim-${n}`,dns_checks:{}}));
const parent={id:'claim-parent',kind:'claim',scope:'source-fixture',status:'running',step:'importing_domains',request:{count:200},result:{requested_count:200,received_count:200,recorded_count:200,processed_count:71}};
for(let n=0;n<200;n++)jobs.set(`hosting-${n}`,{id:`hosting-${n}`,kind:'dns_hosting',scope:domains[n].domain,status:'queued',step:'persisted'});
jobs.set(parent.id,parent);
function node(id){if(!nodes.has(id))nodes.set(id,{innerHTML:'',textContent:'',value:'',checked:false,disabled:false,dataset:{},style:{},classList:{toggle(){}},append(){},focus(){},isConnected:true});return nodes.get(id)}
const context=vm.createContext({console,URL,URLSearchParams,Date:class extends Date{static now(){return clock}},
 document:{body:{classList:{toggle(){}}},activeElement:null,querySelector:node,querySelectorAll:()=>[],createElement:()=>({style:{},remove(){}})},
 localStorage:{getItem:()=>null,removeItem(){}},crypto:{randomUUID:()=> 'fixture'},
 setTimeout:(fn,ms)=>{timers.set(++timerId,{fn,ms});return timerId},clearTimeout:id=>timers.delete(id),setInterval:()=>1,clearInterval(){},
 fetch:async(url,opt={})=>{
  requests.push({url,opt});const u=new URL(url,'https://fixture.test');let data={};
  if(u.pathname==='/api/v1/domain-jobs/status'){
   if(holdStatus)await holdStatus;
   if(failStatus){failStatus=false;return {ok:false,status:502,json:async()=>({detail:'fixture outage'})}}
   const ids=u.searchParams.get('ids').split(',');assert.ok(ids.length<=100);assert.equal(new Set(ids).size,ids.length);
   data={items:ids.map(id=>jobs.get(id)).filter(Boolean).map(j=>structuredClone(j))};
  }else if(u.pathname.startsWith('/api/v1/domain-jobs/'))data=structuredClone(jobs.get(u.pathname.split('/').at(-1)));
  else if(u.pathname.endsWith('/domain-jobs')){
   const all=[...jobs.values()],active=all.filter(j=>['queued','running'].includes(j.status)),counts={};for(const j of all)counts[j.status]=(counts[j.status]||0)+1;
   data={items:[all.at(-1)],total:all.length,status_counts:counts,active_domain_jobs:active.filter(j=>['dns_hosting','claim_setup'].includes(j.kind)),active_claim_jobs:active.filter(j=>j.kind==='claim'),blocked_claim_sources:active.some(j=>j.kind==='claim')?['source-fixture']:[]};
  }else if(u.pathname.endsWith('/mail-domains'))data=domains;
  else if(u.pathname.endsWith('/domain-sources'))data={items:[]};
  else if(u.pathname.endsWith('/dns-credentials'))data={items:[]};
  else if(u.pathname.endsWith('/domain-claims'))data={items:[]};
  return {ok:true,status:200,json:async()=>structuredClone(data)};
 }});
vm.runInContext(script+'\nglobalThis.t={state,controlPage,refreshControlLists,controlJobWatchers,logout};globalThis.notices=[];toast=(text,bad)=>notices.push({text,bad});',context);
const t=context.t;t.state.token='fixture-session';t.state.tab='control';
const refreshes=()=>requests.filter(r=>r.url==='/api/v1/mail-domains').length;
const snapshots=()=>requests.filter(r=>r.url.startsWith('/api/v1/domain-jobs/status?')).length;
async function tick(){assert.equal(timers.size,1,'Every batch shares exactly one timer');const [id,timer]=[...timers.entries()][0];timers.delete(id);clock+=2000;await timer.fn()}
(async()=>{
 await t.controlPage();assert.equal(t.controlJobWatchers.size,201);assert.equal(t.state.controlBusyCounts.size,200);
 assert.match(node('#control-job-progress').textContent,/已保存 200\/200，已处理 71\/200/);
 t.state.controlDns.query='bulk';node('#modal-root').innerHTML='Keep a newer dialog';
 let count=snapshots();await tick();assert.equal(snapshots()-count,3,'201 jobs need three bounded requests, not 201');
 const unchanged=refreshes();
 for(let n=0;n<155;n++)await tick();
 assert.equal(t.controlJobWatchers.size,201,'A queued batch must survive the previous five-minute cutoff');
 assert.equal(t.state.controlBusyCounts.size,200);assert.equal(refreshes(),unchanged,'Unchanged progress must not reload every list');
 parent.result.processed_count=75;await tick();assert.equal(refreshes(),unchanged+1);assert.match(node('#control-job-progress').textContent,/已处理 75\/200/);
 const before=refreshes();await Promise.all([t.refreshControlLists(),t.refreshControlLists(),t.refreshControlLists()]);assert.equal(refreshes(),before+1,'Concurrent refresh callers share one request set');
 failStatus=true;await tick();assert.equal(t.controlJobWatchers.size,201,'A read failure must retain queued jobs and row locks');
 for(const j of jobs.values())if(j.kind==='dns_hosting')j.status='succeeded';
 parent.status='succeeded';parent.result.items=domains.map((d,n)=>({domain:d.domain,dns_hosting_job:{id:`hosting-${n}`,kind:'dns_hosting',scope:d.domain,status:'queued'}}));
 const endRefresh=refreshes();await tick();
 assert.equal(refreshes(),endRefresh+1,'Two hundred completions trigger one list refresh');
 assert.equal(t.controlJobWatchers.size,0,'A stale parent result must not re-watch completed child jobs');assert.equal(t.state.controlBusyCounts.size,0);assert.equal(timers.size,0);
 assert.equal(t.state.controlDns.query,'bulk');assert.equal(node('#modal-root').innerHTML,'Keep a newer dialog');
 assert.equal(requests.filter(r=>r.opt.method==='POST').length,0,'Reloading and polling must not claim or write DNS');
 assert.equal(requests.filter(r=>/\/domain-jobs\/hosting-/.test(r.url)).length,0);
 assert.equal(context.notices.length,0,'Background progress must stay quiet');
 // Bulk import hands off to provider setup, then to hosting, retaining one lock per row.
 jobs.clear();
 for(let n=0;n<200;n++)jobs.set(`setup-${n}`,{id:`setup-${n}`,kind:'claim_setup',scope:domains[n].domain,status:'queued',step:'persisted'});
 await t.controlPage();assert.equal(t.controlJobWatchers.size,200);assert.equal(t.state.controlBusyCounts.size,200);
 assert.match(node('#control-job-progress').textContent,/域名自动流程：200 个域名，200 个排队/);
 for(let n=0;n<200;n++){
  const child={id:`hosting-${n}`,kind:'dns_hosting',scope:domains[n].domain,status:'queued'};jobs.set(child.id,child);
  Object.assign(jobs.get(`setup-${n}`),{status:'succeeded',result:{domain:domains[n].domain,dns_hosting_job:child}});
 }
 const handoff=refreshes();await tick();assert.equal(refreshes(),handoff+1);
 assert.equal(t.controlJobWatchers.size,200);assert.equal(t.state.controlBusyCounts.size,200);
 for(const value of t.state.controlBusyCounts.values())assert.equal(value,1,'Setup-to-hosting handoff must retain exactly one lock');
 for(const job of jobs.values())if(job.kind==='dns_hosting')job.status='succeeded';
 await tick();assert.equal(t.controlJobWatchers.size,0);assert.equal(t.state.controlBusyCounts.size,0);
 for(let n=0;n<10;n++)jobs.get(`hosting-${n}`).status='queued';await t.controlPage();
 let release;holdStatus=new Promise(resolve=>release=resolve);const pending=tick();t.logout(false);release();await pending;holdStatus=null;
 assert.equal(t.controlJobWatchers.size,0);assert.equal(timers.size,0);assert.match(node('#app').innerHTML,/登录控制台/);
 console.log('PASS: 200-domain progress/reload, one timer, bounded snapshots, five-minute queue survival, shared refresh, no duplicate child watchers, quiet read-only polling and logout cancellation');
})().catch(error=>{console.error(error);process.exitCode=1});
