const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const script=fs.readFileSync(path.join(__dirname,'../frontend/index.html'),'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const nodes=new Map(),timers=new Map(),requests=[],jobs=new Map();
let timerId=0,jobId=0,failRead=false,deferredRead=null,postStatus='queued';
const domain=name=>({domain:name,enabled:false,dns_provider:'manual',dns_checks:{},receive_ready:false,send_ready:false});
let domains=[{...domain('claimed.test'),claim_id:'claim-fixture',dns_provider:'digitalplat',dns_credential_ref:'credential-claimed',dns_checks:{wildcard_mx:{status:'failed'}},receive_subdomains:true,max_subdomain_depth:2}];
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
   const kind=u.pathname.endsWith('/dns-repair')?'dns_repair':u.pathname.endsWith('/dns-apply')?'dns_apply':u.pathname.endsWith('/dns-validate')?'dns_validate':'claim';
   data={id:'tracked-'+(++jobId),kind,scope:kind==='dns_repair'?'claimed.test':'source-fixture',status:postStatus};
   jobs.set(data.id,{...data});
  }else if(u.pathname.includes('/domain-jobs/')){
   if(deferredRead)await deferredRead;
   if(failRead){failRead=false;return {ok:false,status:502,json:async()=>({detail:'fixture read interrupted'})}}
   data={...jobs.get(u.pathname.split('/').at(-1))};
  }else if(u.pathname.endsWith('/domain-jobs')){
   const counts={};for(const job of jobs.values())counts[job.status]=(counts[job.status]||0)+1;
   data={items:[...jobs.values()].slice(-1),total:jobs.size,status_counts:counts,active_domain_jobs:[...jobs.values()].filter(j=>j.kind==='dns_repair'&&['queued','running'].includes(j.status)),
    blocked_claim_sources:[...jobs.values()].some(j=>['queued','running','unknown'].includes(j.status))?['source-fixture']:[]};
  }else if(u.pathname.endsWith('/mail-domains'))data=domains.slice();
  else if(u.pathname.endsWith('/domain-sources'))data={items:[{id:'source-fixture',name:'SFREG',source_type:'sfreg_mx',client_id:'fixture',enabled:true}]};
  else if(u.pathname.endsWith('/dns-credentials'))data={items:[]};
  return {ok:true,status:opt.method==='POST'?202:200,json:async()=>data};
 }});
vm.runInContext(script+'\nglobalThis.t={state,controlJob,controlPage,controlJobWatchers,runControlBatch,logout,controlDomainReady,controlUnifiedListData,controlJobNotice,controlRepairEligible,repairControlDns,stopControlJobWatchers,renderControlUnifiedResults,controlDomainActivity};',context);
const t=context.t;t.state.token='fixture-session';t.state.tab='control';
const writes=()=>requests.filter(r=>r.opt.method==='POST').length;
const refreshes=()=>requests.filter(r=>r.url==='/api/v1/mail-domains').length;
async function tick(){
 const timer=[...timers.entries()].find(([,value])=>[1000,2000].includes(value.ms));
 assert.ok(timer,'Expected a scheduled job status poll');timers.delete(timer[0]);await timer[1].fn();
}
(async()=>{
 await t.controlPage();
 vm.runInContext('globalThis.notices=[];toast=(text,bad)=>notices.push({text,bad});',context);
 const target=domains[0];
 assert.equal(t.controlRepairEligible(target),true);
 assert.match(node('#control-dns-body').innerHTML,/data-control-dns-repair="claimed.test"/);
 const manual={...target,domain:'manual.test',dns_provider:'manual'};
 const cloudflare={...target,domain:'cf.test',dns_provider:'cloudflare'};
 domains.push(manual,cloudflare);await t.controlPage();
 assert.equal(t.controlRepairEligible(manual),false);
 assert.equal(t.controlRepairEligible(cloudflare),false);
 t.state.controlSelection.add(target.domain);t.state.controlSelection.add(manual.domain);t.state.controlSelection.add(cloudflare.domain);
 const pageMarkup=node('#page').innerHTML;
 await t.runControlBatch('repair');
 t.state.controlDns.status='processing';t.renderControlUnifiedResults();
 const posts=requests.filter(r=>r.url.endsWith('/dns-repair'));
 assert.equal(posts.length,1,'Mixed batches must repair only eligible DigitalPlat rows');
 assert.equal(JSON.parse(posts[0].opt.body).activate_on_success,true);
 assert.equal(t.state.controlBusyCounts.has(target.domain),true);
 const job=[...jobs.values()].at(-1);
 job.status='running';
 job.step='dns_repair_waiting_for_dns';
 await tick();
 assert.match(node('#control-dns-body').innerHTML,/等待 DNS 生效，自动验证中/);
 const noticeCount=context.notices.length;
 await tick();
 assert.equal(context.notices.length,noticeCount,'Propagation polls must not spam toasts');
 await t.repairControlDns(target);
 assert.equal(requests.filter(r=>r.url.endsWith('/dns-repair')).length,1,'Busy rows reject repeated clicks');
 t.stopControlJobWatchers();
 assert.equal(t.state.controlBusyCounts.size,0);
 await t.controlPage();
 assert.equal(t.state.controlBusyCounts.has(target.domain),true,'Reload restores locks from durable active jobs');
 const restoredMarkup=node('#page').innerHTML;
 assert.match(node('#control-dns-body').innerHTML,/data-control-dns-config="claimed.test"[^>]*disabled/);
 Object.assign(target,{enabled:true,receive_ready:true,send_ready:true,subdomain_receive_ready:true,subdomain_send_ready:true});
 target.dns_checks=Object.fromEntries(['mx','spf','dkim','dmarc','smtp_submission','wildcard_mx'].map(k=>[k,{status:'passed'}]));
 job.status='succeeded';job.result={checks:target.dns_checks,validation_status:'passed',repair:{phase:'recreated'}};
 await tick();
 assert.equal(t.state.controlBusyCounts.has(target.domain),false);
 assert.equal(t.controlUnifiedListData().counts.ready,1);
 assert.doesNotMatch(node('#control-dns-body').innerHTML,/claimed.test/);
 assert.equal(node('#page').innerHTML,restoredMarkup,'Completion refreshes list data without rebuilding the page');
 assert.equal(t.controlRepairEligible(target),false);
 assert.match(t.controlJobNotice(job),/修复与验证通过/);
 assert.equal(requests.filter(r=>r.opt.method==='POST'&&!r.url.endsWith('/dns-repair')).length,0,'The browser delegates all DNS writes and retries to the durable repair job');
 t.logout(false);
 console.log('PASS: wildcard repair eligibility, mixed batches, one submission, waiting state, row locks after reload, quiet polling and automatic ready-tab updates');
})().catch(error=>{console.error(error);process.exitCode=1});
