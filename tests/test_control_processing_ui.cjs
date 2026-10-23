const assert=require('node:assert/strict');
const {fixture,gate,until}=require('./test_dns_batch_performance_ui.cjs');
const counts=f=>f.t.controlUnifiedListData().counts;
function expectCounts(f,pending,processing,ready){
 const c=counts(f);
 assert.equal(c.pending,pending);assert.equal(c.processing,processing);assert.equal(c.ready,ready);
 assert.equal(c.all,pending+processing+ready,'Readiness groups must be exclusive and sum to all domains');
}
(async()=>{
 // Clicking configure-and-enable marks the whole selection before any preview/POST ACK.
 const f=fixture(6),preview=gate(),submit=gate();await f.start();
 f.previewGate(preview);f.submitGate(submit);f.previewActions(()=>[{action:'create'}]);
 const markup=f.node('#page').innerHTML,flow=f.t.runControlCompletion();
 expectCounts(f,0,6,0);
 assert.equal(f.t.state.controlDns.status,'pending','Do not unexpectedly switch the current tab');
 assert.doesNotMatch(f.node('#control-dns-body').innerHTML,/data-control-select=/);
 f.t.state.controlDns.status='processing';f.t.renderControlUnifiedResults();
 assert.equal(f.node('#control-dns-count-processing').textContent,'6');
 assert.match(f.node('#control-dns-body').innerHTML,/control-domain-processing">处理中/);
 assert.match(f.node('#control-dns-body').innerHTML,/正在预览和提交配置/);
 assert.match(f.node('#control-dns-body').innerHTML,/data-control-complete="domain-0.test" disabled/);
 assert.equal(f.node('#control-dns-all').disabled,true);
 assert.equal(f.posted('dns-apply').length,0);
 preview.release();await until(()=>f.posted('dns-apply').length===3);expectCounts(f,0,6,0);
 submit.release();await flow;expectCounts(f,0,6,0);
 assert.equal(f.t.state.controlBusyCounts.size,6,'Queued jobs retain the submission locks');
 const jobs=[...f.jobs.values()];
 for(let i=0;i<jobs.length;i++){
  const job=jobs[i],d=f.domains.find(d=>d.domain===job.scope);
  job.status=['succeeded','succeeded','failed','partial','unknown','succeeded'][i];
  if(i<2){Object.assign(d,{enabled:true,receive_ready:true,send_ready:true});job.result={activation:{status:'ready'}}}
  else job.result={checks:{mx:{status:'failed'}},activation:{status:'blocked'}};
 }
 await f.tick();expectCounts(f,4,0,2);
 assert.equal(f.t.state.controlBusyCounts.size,0);
 assert.match(f.node('#control-dns-body').innerHTML,/当前没有处理中的域名/);
 assert.equal(f.node('#page').innerHTML,markup,'State changes update only table data');
 f.t.state.controlDns.status='pending';f.t.renderControlUnifiedResults();
 assert.equal(f.t.controlUnifiedListData().total,4);
 f.t.state.controlDns.status='ready';f.t.renderControlUnifiedResults();
 assert.equal(f.t.controlUnifiedListData().total,2);

 // A rejected single submission leaves no optimistic processing marker.
 const rejected=fixture(1);await rejected.start();
 Object.assign(rejected.domains[0],{enabled:true,receive_ready:true,send_ready:true});
 rejected.fail();const rejection=rejected.t.controlJob('/mail-domains/domain-0.test/dns-validate');
 expectCounts(rejected,0,1,0);
 await assert.rejects(rejection,/fixture submit error/);expectCounts(rejected,0,0,1);
 assert.equal(rejected.t.controlDomainBusy('domain-0.test'),false);

 // Reload discovers durable jobs even when the paged history has no items.
 const restored=fixture(12),kinds=['dns_apply','dns_complete','claim_setup','dns_hosting','dynv6_register','dns_repair','dns_validate'];
 Object.assign(restored.domains[6],{enabled:true,receive_ready:true,send_ready:true});
 Object.assign(restored.domains[7],{enabled:true,receive_ready:true,send_ready:true});
 const active=kinds.map((kind,i)=>({id:`restore-${i}`,kind,scope:restored.domains[i].domain,
  status:i%2?'running':'queued',automatic:false,read_only:kind==='dns_validate'}));
 Object.assign(active[0],{wait_reason:'provider_cooldown',wait_until:Date.now()/1000+60});
 Object.assign(active[1],{status:'queued',step:'dns_completion_waiting_delegation',wait_reason:'retry_at'});
 active.push({id:'automatic-health',kind:'dns_validate',scope:restored.domains[7].domain,status:'running',automatic:true,read_only:true});
 const parent={id:'auto-claim',kind:'claim',scope:'source-auto',status:'running',request:{configure_on_success:true},
  result:{items:[{domain:restored.domains[8].domain},{domain:restored.domains[9].domain}]}};
 const onlyClaim={id:'only-claim',kind:'claim',scope:'source-only',status:'running',request:{count:1},result:{items:[{domain:restored.domains[11].domain}]}};
 const snapshot={active_domain_jobs:active,active_claim_jobs:[parent,onlyClaim]};
 const claims=[{id:'imported-claim',job_id:parent.id,domain:restored.domains[10].domain,status:'imported'}];
 restored.activeJobs(snapshot);restored.claims(claims);await restored.t.controlPage();
 expectCounts(restored,1,10,1);
 assert.equal(restored.t.controlDomainGroup(restored.domains[6]),'processing','Manual revalidation takes precedence over old ready flags');
 assert.equal(restored.t.controlDomainGroup(restored.domains[7]),'ready','Automatic health checks preserve readiness grouping');
 assert.equal(restored.t.controlDomainGroup(restored.domains[11]),'pending','Claim-only does not imply automatic configuration');
 restored.t.state.controlDns.status='processing';restored.t.renderControlUnifiedResults();
 assert.equal(restored.t.controlUnifiedListData().total,10);
 assert.match(restored.node('#control-dns-body').innerHTML,/等待父区 NS 委派生效/);
 assert.match(restored.node('#control-dns-body').innerHTML,/领取后自动配置排队中/);
 restored.t.state.controlDns.query='domain-10.test';restored.t.renderControlUnifiedResults();
 assert.equal(restored.t.controlUnifiedListData().total,1);
 assert.equal(counts(restored).all,1);assert.equal(counts(restored).processing,1);
 restored.t.state.controlDns.query='';await restored.t.refreshControlLists();expectCounts(restored,1,10,1);
 const fresh=fixture(12);fresh.domains.forEach((d,i)=>Object.assign(d,restored.domains[i]));
 fresh.activeJobs(snapshot);fresh.claims(claims);fresh.t.state.controlDns.status='processing';await fresh.t.controlPage();
 expectCounts(fresh,1,10,1);assert.equal(fresh.t.controlUnifiedListData().total,10);
 for(const instance of [restored,fresh]){
  assert.equal(instance.requests.some(r=>r.opt.method==='POST'),false,'Restoring state must be read-only');
  instance.t.stopControlJobWatchers();expectCounts(instance,10,0,2);
 }

 // The auto-claim parent and configuration child hand off the same domain.
 const claim=fixture(1),domain=claim.domains[0].domain;
 const child={id:'claim-setup',kind:'claim_setup',scope:domain,status:'queued'};
 const claiming={id:'claim-parent',kind:'claim',scope:'source-fixture',status:'running',request:{configure_on_success:true},
  result:{recorded_count:1,items:[{domain}]}};
 claim.activeJobs({active_claim_jobs:[claiming]});claim.jobs.set(claiming.id,claiming);
 await claim.t.controlPage();expectCounts(claim,0,1,0);
 claiming.status='succeeded';claiming.result.items[0].claim_setup_job=child;
 claim.jobs.set(child.id,child);claim.activeJobs({active_domain_jobs:[child]});
 await claim.tick();expectCounts(claim,0,1,0);
 assert.equal(claim.t.controlJobWatchers.has(claiming.id),false);assert.equal(claim.t.controlJobWatchers.has(child.id),true);
 child.status='failed';child.error_code='fixture-setup-failed';claim.activeJobs({});
 await claim.tick();expectCounts(claim,1,0,0);
 assert.equal(claim.t.state.controlBusyCounts.size,0);

 // A mixed workflow banner covers all stages and deduplicates overlapping jobs.
 const progress=fixture(6),activeProgress=[
  {id:'progress-setup',kind:'claim_setup',scope:'domain-0.test',status:'queued'},
  {id:'progress-register',kind:'dynv6_register',scope:'domain-1.test',status:'running'},
  {id:'progress-apply',kind:'dns_apply',scope:'domain-2.test',status:'running'},
  {id:'progress-overlap',kind:'claim_setup',scope:'domain-2.test',status:'queued'},
  {id:'progress-delegation',kind:'dns_complete',scope:'domain-3.test',status:'queued',wait_reason:'retry_at'},
  {id:'progress-validate',kind:'dns_validate',scope:'domain-4.test',status:'queued'},
  {id:'progress-auto',kind:'dns_validate',scope:'domain-5.test',status:'running',automatic:true},
 ];
 progress.activeJobs({active_domain_jobs:activeProgress});await progress.t.controlPage();
 assert.match(progress.node('#control-job-progress').textContent,/域名自动流程：5 个域名，2 个排队，2 个执行中，1 个等待生效或重试/);
 assert.match(progress.node('#control-job-progress').textContent,/后台自动验证/);
 assert.doesNotMatch(progress.node('#control-job-progress').textContent,/域名后台准备/);
 assert.equal(progress.requests.some(r=>r.opt.method==='POST'),false);
 const keyWait=fixture(1);
 keyWait.activeJobs({active_domain_jobs:[{id:'waiting-key',kind:'claim_setup',scope:'domain-0.test',status:'queued',
  wait_reason:'retry_at',step:'claim_waiting_dkim',wait_until:Date.now()/1000+30}]});await keyWait.t.controlPage();
 assert.match(keyWait.node('#control-job-progress').textContent,/1 个域名，0 个排队，0 个执行中，1 个等待生效或重试/);
 keyWait.t.state.controlDns.status='processing';keyWait.t.renderControlUnifiedResults();
 assert.match(keyWait.node('#control-dns-body').innerHTML,/等待 DKIM 公钥生成，将自动继续配置/);
 progress.t.stopControlJobWatchers();keyWait.t.stopControlJobWatchers();

 // Logout during preview clears both optimistic markers and row locks.
 const cancelled=fixture(4),waiting=gate();await cancelled.start();cancelled.previewGate(waiting);
 const abandoned=cancelled.t.runControlCompletion();expectCounts(cancelled,0,4,0);
 cancelled.t.logout(false);waiting.release();await abandoned;
 assert.equal(cancelled.t.controlUnifiedListData().counts.processing,0);
 assert.equal(cancelled.t.state.controlBusyCounts.size,0);
 assert.equal(cancelled.posted('dns-apply').length,0);
 console.log('PASS: immediate processing before ACK; exclusive counts; lock handoff; queued/delegation/cooldown states; durable reload and auto-claim import; automatic health checks excluded; success/failure/unknown cleanup; cancellation');
})().catch(error=>{console.error(error);process.exitCode=1});
