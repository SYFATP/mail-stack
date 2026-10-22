const assert=require('node:assert/strict');
const {fixture}=require('./test_dns_batch_performance_ui.cjs');
(async()=>{
 const f=fixture(2);await f.start();await f.t.runControlCompletion();
 const parents=[...f.jobs.values()];assert.equal(parents.length,2);
 for(const [i,job] of parents.entries()){
  const child={id:'complete-'+i,kind:'dns_complete',scope:job.scope,status:'queued',step:'dns_completion_waiting_delegation',wait_reason:'retry_at',wait_until:Date.now()/1000+60};
  f.jobs.set(child.id,child);job.status='succeeded';job.result={domain:job.scope,completion_job:child};
 }
 await f.tick();
 assert.equal(f.t.state.controlBatches.size,1,'A DNS apply result must not finish a batch before delegation and validation');
 assert.equal(f.t.state.controlBusyCounts.size,2,'Row locks transfer to durable completion');
 assert.equal(f.t.controlJobWatchers.size,2);assert.ok([...f.t.controlJobWatchers.values()].every(w=>w.kind==='dns_complete'));
 assert.match(f.node('#control-dns-body').innerHTML,/等待父区 NS 委派生效/);
 assert.equal(f.notices.filter(n=>/完成：/.test(n.text)).length,0);
 for(const watcher of f.t.controlJobWatchers.values())watcher.attempts=1800;
 await f.tick();assert.equal(f.t.controlJobWatchers.size,2,'Completion tracking must cover the backend two-hour deadline');
 assert.equal(f.t.state.controlBatches.size,1);
 const complete=[...f.jobs.values()].filter(j=>j.kind==='dns_complete');
 complete[0].status='succeeded';complete[0].result={activation:{status:'ready'},checks:{mx:{status:'passed'}}};
 complete[1].status='partial';complete[1].error_code='dns_publication_timeout';complete[1].result={};
 await f.tick();
 assert.equal(f.t.state.controlBatches.size,0);assert.equal(f.t.state.controlBusyCounts.size,0);
 assert.match(f.notices.at(-1).text,/已就绪 1，待处理 1/);
 assert.match(f.node('#control-dns-body').innerHTML,/等待解析超时/);
 f.t.stopControlJobWatchers();
 console.log('PASS: delegation completion child tracking; continuous row locks; no premature success; final batch summary and retry status');
})().catch(error=>{console.error(error);process.exitCode=1});
