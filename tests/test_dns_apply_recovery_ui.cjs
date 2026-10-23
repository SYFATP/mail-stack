const assert=require('node:assert/strict');
const {fixture}=require('./test_dns_batch_performance_ui.cjs');
(async()=>{
 const f=fixture(2);await f.start();await f.t.runControlCompletion();
 const jobs=[...f.jobs.values()];
 for(const [i,job] of jobs.entries())Object.assign(job,{
  status:'queued',step:i?'dns_apply_waiting_upstream':'dns_apply_readback_pending',
  wait_reason:'retry_at',wait_until:Date.now()/1000+60,
  result:{apply_recovery:{deadline:Date.now()/1000+1800}}
 });
 await f.tick();
 assert.equal(f.t.controlUnifiedListData().counts.processing,2);
 assert.equal(f.t.state.controlBusyCounts.size,2);
 f.t.state.controlDns.status='processing';f.t.renderControlUnifiedResults();
 assert.match(f.node('#control-dns-body').innerHTML,/DNS 写入结果待回查/);
 assert.match(f.node('#control-dns-body').innerHTML,/上游读取暂时失败/);
 assert.equal(f.notices.filter(n=>/完成：/.test(n.text)).length,0);
 jobs[0].status='running';
 f.t.controlJobWatchers.get(jobs[0].id).attempts=160;
 await f.tick();
 assert.equal(f.t.controlUnifiedListData().counts.processing,2,
  'Resuming after a long readback wait must not hit the ordinary short watcher limit');
 jobs[0].status='queued';

 // A page reload restores the actual durable wait and keeps both rows locked.
 const reloaded=fixture(2);
 reloaded.activeJobs({active_domain_jobs:jobs});
 reloaded.t.state.controlDns.status='processing';await reloaded.t.controlPage();
 assert.equal(reloaded.t.controlUnifiedListData().counts.processing,2);
 assert.equal(reloaded.t.controlDomainBusy(jobs[0].scope),true);
 assert.match(reloaded.node('#control-dns-body').innerHTML,/DNS 写入结果待回查/);
 reloaded.t.stopControlJobWatchers();

 jobs[0].status='succeeded';
 const child={id:'recovery-completion',kind:'dns_complete',scope:jobs[0].scope,
  status:'queued',step:'dns_completion_waiting_delegation',wait_reason:'retry_at'};
 jobs[0].result={domain:jobs[0].scope,completion_job:child};f.jobs.set(child.id,child);
 jobs[1].status='unknown';jobs[1].error_code='dns_write_unconfirmed';
 await f.tick();
 assert.equal(f.t.controlUnifiedListData().counts.processing,1);
 assert.equal(f.t.state.controlBusyCounts.size,1);
 f.t.state.controlDns.status='pending';f.t.renderControlUnifiedResults();
 assert.match(f.node('#control-dns-body').innerHTML,/DNS 写入结果回查超时/);
 Object.assign(f.domains[0],{enabled:true,receive_ready:true,send_ready:true});
 child.status='succeeded';child.result={activation:{status:'ready'}};
 await f.tick();
 assert.equal(f.t.controlUnifiedListData().counts.ready,1);
 assert.equal(f.t.controlUnifiedListData().counts.processing,0);
 f.t.stopControlJobWatchers();
 console.log('PASS: durable DNS readback/upstream waits keep processing and row locks across reload; completion handoff and bounded failure');
})().catch(error=>{console.error(error);process.exitCode=1});
