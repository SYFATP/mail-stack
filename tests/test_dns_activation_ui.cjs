const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const script=fs.readFileSync(path.join(__dirname,'../frontend/index.html'),'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const nodes=new Map(),timers=new Map(),requests=[],jobs=new Map();
let timerId=0,jobId=0,failRead=false,deferredRead=null,postStatus='queued';
const domain=name=>({domain:name,enabled:false,dns_provider:'manual',dns_checks:{},receive_ready:false,send_ready:false});
let domains=[{...domain('claimed.test'),claim_id:'claim-fixture',dns_provider:'digitalplat',dns_credential_ref:'credential-claimed',receive_subdomains:true,max_subdomain_depth:2}];
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
vm.runInContext(script+'\nglobalThis.t={state,controlJob,controlPage,controlJobWatchers,runControlBatch,logout,controlDomainReady,controlUnifiedListData,controlJobNotice};',context);
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
 t.state.controlCredentials.push({id:'credential-claimed',provider:'digitalplat'});
 t.state.controlSelection.add('claimed.test');
 const pageMarkup=node('#page').innerHTML;
 await t.runControlBatch('configure');
 const request=requests.find(r=>r.url.endsWith('/dns-apply'));
 assert.equal(JSON.parse(request.opt.body).activate_on_success,true,'A claimed disabled domain must carry durable activation intent');
 const job=[...jobs.values()].at(-1),d=domains[0];
 job.status='succeeded';job.result={validation_status:'passed',activation:{status:'routing_pending',enabled:true},checks:Object.fromEntries(['mx','spf','dkim','dmarc','smtp_submission','wildcard_mx'].map(name=>[name,{status:'passed'}]))};
 d.enabled=true;d.dns_checks=Object.fromEntries(['mx','spf','dkim','dmarc','smtp_submission','wildcard_mx'].map(name=>[name,{status:'passed'}]));
 await tick();
 assert.equal(t.controlJobWatchers.size,1,'Keep the watcher while Postfix routing is pending');
 assert.equal(t.state.controlBusyCounts.has(d.domain),true,'Wait for actual readiness before unlocking the row');
 assert.equal(t.controlUnifiedListData().counts.ready,0);
 Object.assign(d,{receive_ready:true,send_ready:true,subdomain_receive_ready:true,subdomain_send_ready:true});
 await tick();
 assert.equal(t.controlJobWatchers.size,0);
 assert.equal(t.state.controlBusyCounts.size,0);
 assert.equal(t.controlUnifiedListData().counts.ready,1);
 assert.equal(t.controlUnifiedListData().counts.pending,0);
 assert.doesNotMatch(node('#control-dns-body').innerHTML,/claimed.test/,'Ready domains leave the pending tab automatically');
 assert.equal(t.state.controlSelection.size,0,'Selection follows the status tab');
 assert.equal(node('#page').innerHTML,pageMarkup,'Only list data refreshes; do not rebuild the page');
 assert.match(context.notices.at(-1).text,/已就绪 1/);
 assert.equal(context.notices.at(-1).bad,false);
 const failed={...domain('failed.test'),claim_id:'failed-claim',receive_subdomains:true,max_subdomain_depth:2};
 domains.push(failed);await t.controlPage();t.state.controlSelection.add(failed.domain);
 await t.runControlBatch('validate');
 const validationRequest=requests.filter(r=>r.url.endsWith('/dns-validate')).at(-1);
 assert.equal(JSON.parse(validationRequest.opt.body).activate_on_success,true);
 const failedJob=[...jobs.values()].at(-1);
 failedJob.status='succeeded';failedJob.result={checks:{wildcard_mx:{status:'failed'}},activation:{status:'blocked',enabled:false,pending_checks:['wildcard_mx']}};
 await tick();
 assert.match(node('#control-dns-body').innerHTML,/failed.test/);
 assert.equal(t.controlUnifiedListData().counts.pending,1);
 assert.match(context.notices.at(-1).text,/检查未通过 1/);
 assert.equal(context.notices.at(-1).bad,true);
 assert.equal(requests.some(r=>r.url.includes('/toggle?')),false,'The browser must not separately toggle activation');
 const manual=domain('manual.test');domains.push(manual);await t.controlPage();
 t.state.controlSelection.clear();t.state.controlSelection.add(manual.domain);await t.runControlBatch('validate');
 const manualRequest=requests.filter(r=>r.url.endsWith('/dns-validate')).at(-1);
 assert.equal(JSON.parse(manualRequest.opt.body).activate_on_success,undefined,'Validation retains manual-domain enabled state');
 t.logout(false);
 assert.equal(t.controlJobWatchers.size,0);
 console.log('PASS: claimed DNS operations request durable activation, wait for routing, move ready rows between tabs without page rebuild, and retain failed/manual domains');
})().catch(error=>{console.error(error);process.exitCode=1});
