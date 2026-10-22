const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const script=fs.readFileSync(path.join(__dirname,'../frontend/index.html'),'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const flush=()=>new Promise(resolve=>setImmediate(resolve));
const gate=()=>{let resolve;return {promise:new Promise(r=>resolve=r),release:()=>resolve()}};
function fixture(count=200){
 const nodes=new Map(),requests=[],jobs=new Map(),timers=new Map(),notices=[];
 let nextJob=0,nextTimer=0,previewGate=null,submitGate=null,conflict='',failSubmit=false,previewActive=0,submitActive=0,previewPeak=0,submitPeak=0,expiresAt=0,previewActions=()=>[];
 const domains=Array.from({length:count},(_,n)=>({domain:`domain-${n}.test`,enabled:false,dns_provider:'digitalplat',
  dns_credential_ref:`credential-${n}`,receive_ready:false,send_ready:false,dns_checks:{}}));
 function node(id){if(!nodes.has(id))nodes.set(id,{innerHTML:'',textContent:'',value:'',checked:false,disabled:false,
  dataset:{},style:{},classList:{toggle(){}},append(){},focus(){document.activeElement=this},isConnected:true,
  hidden:false,offsetWidth:350,offsetHeight:250,getBoundingClientRect:()=>({right:950,bottom:100}),
  matches(){return !!this.open},showPopover(){this.open=true;this.ontoggle?.({newState:'open'})},
  hidePopover(){this.open=false;this.ontoggle?.({newState:'closed'})},togglePopover(){this.open?this.hidePopover():this.showPopover()},
  querySelectorAll:selector=>menuItems(selector)});return nodes.get(id)}
 function menuItems(selector){
  if(selector!=='[data-control-bulk-menu]')return [];
  return ['digitalplat','cloudflare','dynv6','all','more-dynv6','more-repair'].map(key=>{
   const more=key.startsWith('more-'),item=node(more?'#control-bulk-'+key.slice(5):'#control-config-'+key);
   item.dataset.controlBulkMenu=more?'more':'configure';return item;
  });
 }
 const document={body:{classList:{toggle(){}}},activeElement:null,documentElement:{clientWidth:1024,clientHeight:768},
  querySelector:id=>node(id),querySelectorAll:selector=>menuItems(selector),createElement:()=>({style:{},remove(){}})};
 const context=vm.createContext({document,console,URL,URLSearchParams,
  localStorage:{getItem:()=>null,removeItem(){}},crypto:{randomUUID:()=>`fixture-${requests.length}`},
  setTimeout:(fn,ms)=>{timers.set(++nextTimer,{fn,ms});return nextTimer},clearTimeout:id=>timers.delete(id),setInterval:()=>1,clearInterval(){},
  fetch:async(url,opt={})=>{
   requests.push({url,opt});const u=new URL(url,'https://fixture.test');let data={};
   const name=decodeURIComponent(u.pathname.match(/\/mail-domains\/([^/]+)/)?.[1]||'');
   if(opt.method==='POST'&&u.pathname.endsWith('/dns-preview')){
    previewActive++;previewPeak=Math.max(previewPeak,previewActive);
    try{if(previewGate)await (typeof previewGate==='function'?previewGate(name):previewGate.promise);await flush()}finally{previewActive--}
    const domain=domains.find(d=>d.domain===name);
    data={id:`plan-${name}`,domain:name,credential_ref:domain?.dns_credential_ref,provider:domain?.dns_provider,executable:name!==conflict,expires_at:expiresAt,actions:previewActions(name),conflicts:name===conflict?[{code:'foreign_record_conflict'}]:[]};
   }else if(opt.method==='POST'){
    submitActive++;submitPeak=Math.max(submitPeak,submitActive);
    try{
     if(failSubmit){failSubmit=false;return {ok:false,status:502,json:async()=>({detail:'fixture submit error'})}}
     if(submitGate)await submitGate.promise;await flush();
     data={id:`job-${++nextJob}`,kind:'dns_apply',scope:name,status:'queued'};jobs.set(data.id,{...data});
    }finally{submitActive--}
   }else if(u.pathname.endsWith('/domain-jobs/status'))data={items:u.searchParams.get('ids').split(',').map(id=>jobs.get(id))};
   else if(u.pathname.includes('/domain-jobs/'))data=jobs.get(u.pathname.split('/').at(-1));
   else if(u.pathname.endsWith('/domain-jobs'))data={items:[],total:jobs.size,status_counts:{},blocked_claim_sources:[]};
   else if(u.pathname.endsWith('/mail-domains'))data=domains;
   else if(u.pathname.endsWith('/domain-sources')||u.pathname.endsWith('/domain-claims'))data={items:[]};
   else if(u.pathname.endsWith('/dns-credentials'))data={items:domains.filter(d=>d.dns_credential_ref).map(d=>({id:d.dns_credential_ref,provider:d.dns_provider,domain:d.domain}))};
   return {ok:true,status:opt.method==='POST'?202:200,json:async()=>data};
  }});
 vm.runInContext(script+'\nglobalThis.t={state,controlPage,runControlBatch,runControlCompletion,continueControlDomain,showSourceClaimDialog,watchClaimHostingJobs,renderControlUnifiedResults,controlConfigEligible,lockControlDomain,unlockControlDomain,controlJobWatchers,stopControlJobWatchers,logout};',context);
 context.collect=(text,bad)=>notices.push({text,bad});vm.runInContext('toast=collect;',context);
 const t=context.t;t.state.token='fixture-session';t.state.tab='control';
 const posted=kind=>requests.filter(r=>r.opt.method==='POST'&&r.url.endsWith('/'+kind));
 return {t,node,document,requests,jobs,domains,notices,posted,async start(){await t.controlPage();domains.forEach(d=>t.state.controlSelection.add(d.domain));t.renderControlUnifiedResults()},
  previewGate:v=>previewGate=v,previewActions:v=>previewActions=v,submitGate:v=>submitGate=v,conflict:v=>conflict=v,expires:v=>expiresAt=v,fail:()=>failSubmit=true,
  peaks:()=>({previewPeak,submitPeak}),async tick(){const entry=[...timers.entries()].find(([,v])=>[1000,2000].includes(v.ms));assert.ok(entry);timers.delete(entry[0]);await entry[1].fn()}};
}
async function until(predicate){for(let n=0;n<1000&&!predicate();n++)await flush();assert.ok(predicate(),'Expected asynchronous phase');}
module.exports={fixture,gate,flush,until};
if(require.main===module)(async()=>{
 const f=fixture(),previews=gate(),submits=gate();await f.start();f.previewGate(previews);f.submitGate(submits);
 const running=f.t.runControlBatch('configure');await flush();
 assert.equal(f.posted('dns-preview').length,3);assert.equal(f.posted('dns-apply').length,0);
 assert.equal(f.t.state.controlBusyCounts.size,200);assert.match(f.node('#control-job-progress').textContent,/DNS 预览 0\/200/);
 previews.release();await until(()=>f.posted('dns-apply').length===3);
 assert.equal(f.posted('dns-preview').length,200,'All previews must pass before any apply is submitted');
 assert.equal(f.peaks().previewPeak,3);assert.equal(f.peaks().submitPeak,3);assert.equal(f.t.state.controlBusyCounts.size,200);
 submits.release();await running;
 assert.equal(f.posted('dns-apply').length,200);assert.equal(f.peaks().submitPeak,3);assert.equal(f.t.controlJobWatchers.size,200);
 for(const value of f.t.state.controlBusyCounts.values())assert.equal(value,1,'Submission hands each lock to its watcher exactly once');
 assert.match(f.node('#control-job-progress').textContent,/200 条排队/);
 for(const job of f.jobs.values()){job.status='succeeded';job.result={checks:{mx:{status:'passed'}},validation_status:'passed'}}
 await f.tick();assert.equal(f.t.state.controlBusyCounts.size,0);assert.equal(f.t.state.controlBatches.size,0);
 assert.equal(f.notices.filter(n=>n.text.includes('完成')).length,1);assert.equal(f.posted('dns-apply').length,200);
 assert.equal(f.node('#control-job-progress').hidden,true);
 const c=fixture(200);await c.start();c.conflict('domain-7.test');await c.t.runControlBatch('configure');
 assert.equal(c.posted('dns-apply').length,0,'A single conflict must stop automatic DNS writes');assert.equal(c.t.state.controlBusyCounts.size,0);assert.equal(c.t.state.controlBatches.size,0);
 assert.match(c.node('#modal-root').innerHTML,/预览通过 <strong>199<\/strong>/);assert.match(c.node('#modal-root').innerHTML,/需处理 <strong>1<\/strong>/);
 assert.match(c.node('#modal-root').innerHTML,/应用 199 个通过项/);assert.match(c.node('#modal-root').innerHTML,/<details><summary>查看 199/);
 const applyPassed=c.node('#control-apply-passed').onclick;await applyPassed();await applyPassed();
 assert.equal(c.posted('dns-apply').length,199);assert.equal(c.posted('dns-preview').length,200,'Reuse the reviewed immutable plans');
 assert.equal(c.posted('dns-apply').some(r=>r.url.includes('domain-7.test/')),false,'Never submit the failed item');
 assert.equal(c.t.state.controlBusyCounts.size,199);assert.equal(c.node('#modal-root').innerHTML,'');c.t.stopControlJobWatchers();
 const allBad=fixture(1);await allBad.start();allBad.conflict('domain-0.test');await allBad.t.runControlBatch('configure');
 assert.doesNotMatch(allBad.node('#modal-root').innerHTML,/id="control-apply-passed"/);assert.equal(allBad.posted('dns-apply').length,0);
 const expired=fixture(3);await expired.start();expired.conflict('domain-0.test');expired.expires(1);await expired.t.runControlBatch('configure');
 await expired.node('#control-apply-passed').onclick();assert.equal(expired.posted('dns-apply').length,0);assert.match(expired.notices.at(-1).text,/已过期/);
 const changed=fixture(3);await changed.start();changed.conflict('domain-0.test');await changed.t.runControlBatch('configure');
 changed.t.state.controlDomains[1].dns_credential_ref='replacement-credential';
 await changed.node('#control-apply-passed').onclick();assert.equal(changed.posted('dns-apply').length,0);assert.match(changed.notices.at(-1).text,/配置已变化/);
 const stale=fixture(3);await stale.start();stale.conflict('domain-0.test');await stale.t.runControlBatch('configure');
 const abandonedContinue=stale.node('#control-apply-passed').onclick;stale.t.logout(false);await abandonedContinue();assert.equal(stale.posted('dns-apply').length,0);
 const cancelled=fixture(12),wait=gate();await cancelled.start();cancelled.previewGate(wait);
 const abandoned=cancelled.t.runControlBatch('configure');await flush();cancelled.t.logout(false);wait.release();await abandoned;
 assert.equal(cancelled.posted('dns-preview').length,3);assert.equal(cancelled.posted('dns-apply').length,0);assert.equal(cancelled.t.state.controlBusyCounts.size,0);
 const partial=fixture(12),pending=gate();await partial.start();partial.submitGate(pending);partial.fail();
 let settled=false;const interrupted=partial.t.runControlBatch('configure').then(()=>settled=true);
 await until(()=>partial.posted('dns-apply').length===3);await flush();
 assert.equal(settled,false,'Wait for the other accepted submissions before releasing holds');assert.equal(partial.t.state.controlBusyCounts.size,12);
 pending.release();await interrupted;
 assert.equal(partial.posted('dns-apply').length,3,'Stop scheduling after a failed submission');assert.equal(partial.t.controlJobWatchers.size,2);
 assert.equal(partial.t.state.controlBusyCounts.size,2,'Accepted jobs must retain their locks');partial.t.stopControlJobWatchers();
 // Provider-specific menu actions must fence both previews and locks to their own rows.
 const mixed=fixture(8);
 mixed.domains.forEach((d,i)=>d.dns_provider=['digitalplat','cloudflare','dynv6'][i%3]);
 mixed.domains[6].dns_provider='manual';mixed.domains[7].dns_credential_ref=null;
 await mixed.start();
 mixed.t.state.controlCredentials.find(c=>c.id==='credential-4').provider='digitalplat';
 mixed.t.state.controlCredentials.find(c=>c.id==='credential-3').domain='another.test';
 mixed.t.renderControlUnifiedResults();
 assert.equal(mixed.node('#control-bulk-configure').textContent,'配置 DNS ⌄');
 assert.match(mixed.node('#control-bulk-hint').textContent,/4 个需手动配置或补齐凭据/);
 assert.equal(mixed.t.controlConfigEligible(mixed.domains[3]),false,'Domain-scoped credentials must match');
 assert.equal(mixed.t.controlConfigEligible(mixed.domains[4]),false,'Credentials must match the current provider');
 mixed.node('#control-bulk-configure').onclick();
 assert.equal(mixed.node('#control-bulk-configure-menu').open,true);
 assert.equal(mixed.node('#control-bulk-configure').ariaExpanded,'true');
 assert.equal(mixed.document.activeElement,mixed.node('#control-config-digitalplat'));
 mixed.node('#control-bulk-configure-menu').onkeydown({key:'ArrowDown',preventDefault(){}});
 assert.equal(mixed.document.activeElement,mixed.node('#control-config-cloudflare'));
 mixed.node('#control-bulk-configure-menu').onkeydown({key:'End',preventDefault(){}});
 assert.equal(mixed.document.activeElement,mixed.node('#control-config-all'));
 mixed.node('#control-bulk-configure-menu').onkeydown({key:'Escape',preventDefault(){},stopPropagation(){}});
 assert.equal(mixed.node('#control-bulk-configure-menu').open,false);
 assert.equal(mixed.document.activeElement,mixed.node('#control-bulk-configure'));
 const providerWait=gate();mixed.previewGate(providerWait);
 const providerRun=mixed.node('#control-config-dynv6').onclick();await flush();
 assert.deepEqual(mixed.posted('dns-preview').map(r=>r.url.match(/mail-domains\/([^/]+)/)[1]).sort(),['domain-2.test','domain-5.test']);
 assert.deepEqual([...mixed.t.state.controlBusyCounts.keys()].sort(),['domain-2.test','domain-5.test']);
 assert.equal(mixed.node('#control-bulk-configure').textContent,'配置 DNS ⌄');
 assert.equal(mixed.node('#control-config-dynv6').disabled,true);
 providerWait.release();await providerRun;mixed.previewGate(null);
 assert.deepEqual(mixed.posted('dns-apply').map(r=>JSON.parse(r.opt.body).plan_id).sort(),['plan-domain-2.test','plan-domain-5.test']);
 mixed.t.stopControlJobWatchers();
 const allProviders=fixture(3);allProviders.domains.forEach((d,i)=>d.dns_provider=['digitalplat','cloudflare','dynv6'][i]);
 await allProviders.start();
 await allProviders.node('#control-config-all').onclick();
 assert.equal(allProviders.posted('dns-apply').length,3);
 assert.deepEqual(allProviders.domains.map(d=>d.dns_provider),['digitalplat','cloudflare','dynv6']);
 allProviders.t.stopControlJobWatchers();
 allProviders.t.state.controlSelection.clear();allProviders.t.state.controlSelection.add('domain-1.test');
 allProviders.t.renderControlUnifiedResults();
 assert.equal(allProviders.node('#control-bulk-configure').textContent,'配置 Cloudflare');
 assert.equal(allProviders.node('#control-bulk-configure').ariaHasPopup,'false');
 allProviders.domains[1].enabled=true;allProviders.t.renderControlUnifiedResults();
 assert.equal(allProviders.node('#control-bulk-more').disabled,false,'Step-by-step validation stays available for enabled domains');
 allProviders.t.lockControlDomain('domain-1.test');allProviders.t.renderControlUnifiedResults();
 assert.equal(allProviders.node('#control-bulk-configure').disabled,true);assert.equal(allProviders.node('#control-bulk-validate').disabled,true);
 assert.match(allProviders.node('#control-bulk-hint').textContent,/正在执行任务/);
 allProviders.t.unlockControlDomain('domain-1.test');
 console.log('PASS: provider-specific labels, menu keyboard/focus, credential scoping, mixed-provider preview/apply and lock isolation, configure-all preserves providers, busy/unsupported controls');
 console.log('PASS: 200 DNS previews/submissions bounded to 3, all-preview conflict barrier, visible progress, row lock handoff, aggregate completion, cancellation and settled partial submissions');
})().catch(error=>{console.error(error);process.exitCode=1});
