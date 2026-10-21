const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const script=fs.readFileSync(path.join(__dirname,'../frontend/index.html'),'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
function fixture(){
 const nodes=new Map(),requests=[],jobs=new Map(),timers=new Map(),required=new Set(['new.test']);
 let nextJob=0,nextTimer=0,previewError='';
 const domains=['new.test','existing.test'].map(domain=>({domain,enabled:false,dns_provider:'digitalplat',
  dns_credential_ref:domain+'-credential',receive_ready:false,send_ready:false,dns_checks:{}}));
 function node(id){if(!nodes.has(id))nodes.set(id,{innerHTML:'',textContent:'',value:'',checked:false,disabled:false,
  dataset:{},style:{},classList:{toggle(){}},append(){},focus(){},isConnected:true});return nodes.get(id)}
 const document={body:{classList:{toggle(){}}},querySelector:id=>node(id),querySelectorAll:()=>[],
  createElement:()=>({style:{},remove(){}})};
 const context=vm.createContext({document,console,URL,URLSearchParams,
  localStorage:{getItem:()=>null,removeItem(){}},crypto:{randomUUID:()=> 'fixture-'+requests.length},
  setTimeout:(fn,ms)=>{timers.set(++nextTimer,{fn,ms});return nextTimer},clearTimeout:id=>timers.delete(id),
  setInterval:()=>1,clearInterval(){},
  fetch:async(url,opt={})=>{
   requests.push({url,opt});const u=new URL(url,'https://fixture.test');
   const name=decodeURIComponent(u.pathname.match(/\/mail-domains\/([^/]+)/)?.[1]||'');
   let data={};
   if(opt.method==='POST'&&u.pathname.endsWith('/dns-preview')){
    if(previewError||required.has(name))return {ok:false,status:409,json:async()=>({detail:previewError||
     {code:'digitalplat_dns_not_enabled',message:'DNS hosting is not enabled'}})};
    data={id:'plan-'+name,domain:name,executable:true,actions:[],conflicts:[]};
   }else if(opt.method==='POST'){
    const kind=u.pathname.endsWith('/dns-hosting')?'dns_hosting':u.pathname.endsWith('/dns-apply')?'dns_apply':'claim';
    data={id:'job-'+(++nextJob),kind,scope:name||'source-fixture',status:'queued'};
    jobs.set(data.id,{...data});
   }else if(u.pathname.includes('/domain-jobs/'))data=jobs.get(u.pathname.split('/').at(-1));
   else if(u.pathname.endsWith('/domain-jobs'))data={items:[],total:jobs.size,status_counts:{},blocked_claim_sources:[]};
   else if(u.pathname.endsWith('/mail-domains'))data=domains;
   else if(u.pathname.endsWith('/domain-sources'))data={items:[]};
   else if(u.pathname.endsWith('/dns-credentials'))data={items:domains.map(d=>({id:d.dns_credential_ref,provider:'digitalplat',domain:d.domain}))};
   else if(u.pathname.endsWith('/domain-claims'))data={items:[]};
   return {ok:true,status:opt.method==='POST'?202:200,json:async()=>data};
  }});
 vm.runInContext(script+'\nglobalThis.t={state,controlPage,runControlBatch,previewControlDns,controlJob,controlJobWatchers,stopControlJobWatchers};globalThis.notices=[];toast=(text,bad)=>notices.push({text,bad});',context);
 const t=context.t;t.state.token='fixture-session';t.state.tab='control';
 async function tick(){
  const entry=[...timers.entries()].find(([,value])=>[1000,2000].includes(value.ms));
  assert.ok(entry,'Expected a job status poll');timers.delete(entry[0]);await entry[1].fn();
 }
 const posted=kind=>requests.filter(r=>r.opt.method==='POST'&&r.url.endsWith('/'+kind));
 return {t,node,requests,jobs,domains,required,tick,posted,notices:context.notices,error:v=>previewError=v};
}
const flush=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
 const f=fixture();await f.t.controlPage();f.t.state.controlSelection=new Set(['new.test','existing.test']);
 const batch=f.t.runControlBatch('configure');await flush();
 assert.equal(f.posted('dns-hosting').length,1);
 assert.equal(f.posted('dns-apply').length,0,'Do not apply records while hosting is pending');
 assert.ok(f.t.state.controlBusyCounts.has('new.test'));assert.ok(f.t.state.controlBusyCounts.has('existing.test'));
 const hosting=[...f.jobs.values()].find(j=>j.kind==='dns_hosting');
 hosting.status='succeeded';hosting.result={hosting_status:'ready'};f.required.delete('new.test');
 await f.tick();await batch;
 assert.equal(f.posted('dns-hosting').length,1,'Existing Hosted DNS must skip preparation writes');
 assert.equal(f.posted('dns-apply').length,2,'Continue the original batch after preparation and a fresh preview');
 const newPreviews=f.requests.filter(r=>r.url.endsWith('/new.test/dns-preview'));
 assert.equal(newPreviews.length,2,'Discard the failed preview and read a fresh immutable plan');
 assert.ok(f.t.state.controlBusyCounts.has('new.test'),'Apply must retain the row lock');
 for(const job of f.jobs.values())if(job.kind==='dns_apply'){
  job.status='succeeded';job.result={validation_status:'passed',checks:{mx:{status:'passed'}}};
 }
 await f.tick();
 assert.equal(f.t.state.controlBusyCounts.size,0);
 assert.match(f.notices.at(-1).text,/DNS 应用与验证完成/);

 const missing=fixture();await missing.t.controlPage();
 const failed=missing.t.previewControlDns(missing.domains[0]);await flush();
 const failedJob=[...missing.jobs.values()][0];failedJob.status='partial';
 failedJob.error_code='dns_hosting_enable_unconfirmed';
 await missing.tick();await assert.rejects(failed,/请核对 DigitalPlat 托管状态/);
 assert.equal(missing.posted('dns-hosting').length,1);
 assert.equal(missing.posted('dns-apply').length,0);

 const auth=fixture();await auth.t.controlPage();auth.error('provider_http_403');
 await assert.rejects(auth.t.previewControlDns(auth.domains[0]),/403/);
 assert.equal(auth.posted('dns-hosting').length,0,'Only the typed missing-service error authorizes preparation');

 const cancelled=fixture();await cancelled.t.controlPage();
 const abandoned=cancelled.t.previewControlDns(cancelled.domains[0],()=>Boolean(cancelled.t.state.token));
 await flush();cancelled.t.state.token='';cancelled.t.stopControlJobWatchers();
 await assert.rejects(abandoned,/已结束/);
 assert.equal(cancelled.posted('dns-apply').length,0);

 const claimed=fixture();await claimed.t.controlPage();
 const parent=await claimed.t.controlJob('/domain-sources/source-fixture/claim',{count:1,status:'registered'});
 const child={id:'auto-hosting-child',kind:'dns_hosting',scope:'new.test',status:'queued'};
 claimed.jobs.set(child.id,{...child});
 const stored=claimed.jobs.get(parent.id);stored.status='succeeded';
 stored.result={items:[{domain:'new.test',dns_hosting_job:child}]};
 await claimed.tick();
 assert.ok(claimed.t.state.controlBusyCounts.has('new.test'),'Automatically prepare newly claimed rows under a lock');
 assert.equal(claimed.t.controlJobWatchers.size,1);
 assert.match(claimed.notices.at(-1).text,/正在后台准备 DNS 托管/);
 claimed.jobs.get(child.id).status='succeeded';await claimed.tick();
 assert.equal(claimed.t.state.controlBusyCounts.size,0);
 assert.equal(claimed.t.controlJobWatchers.size,0);
 console.log('PASS: Hosted DNS preparation -> fresh preview -> batch apply; pending/credential errors; row locks, automatic claim setup tracking, session cancellation, and no repeated preparation');
})().catch(error=>{console.error(error);process.exitCode=1});
