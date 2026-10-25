const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../frontend/index.html'),'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
function fixture(){
 const nodes=new Map(),requests=[],jobs=new Map(),timers=new Map(),notices=[];
 const domains=['one.test','two.test'].map(domain=>({domain,enabled:false,dns_provider:'digitalplat',dns_checks:{}}));
 const credentials=[{id:'dyn-fixture',label:'dynv6 fixture',provider:'dynv6',session:{configured:true,status:'valid'}}];
 let markup='',gate=null,fail=false,seq=0;
 function node(id){if(!nodes.has(id))nodes.set(id,{innerHTML:'',textContent:'',value:'',disabled:false,checked:false,
  dataset:{},style:{},classList:{toggle(){}},append(){},focus(){},isConnected:true});return nodes.get(id)}
 Object.defineProperty(node('#modal-root'),'innerHTML',{get:()=>markup,set:v=>{markup=v;nodes.delete('#domain-dialog-bg')}});
 const document={body:{classList:{toggle(){}}},querySelector:id=>id==='#domain-dialog-bg'&&!markup?null:node(id),querySelectorAll:()=>[],
  createElement:()=>({style:{},remove(){}})};
 const context=vm.createContext({document,console,URL,URLSearchParams,localStorage:{getItem:()=>null,removeItem(){}},
  crypto:{randomUUID:()=>`fixture-${requests.length}`},setTimeout:(fn,ms)=>{timers.set(++seq,{fn,ms});return seq},
  clearTimeout:id=>timers.delete(id),setInterval:()=>1,clearInterval(){},
  fetch:async(url,opt={})=>{
   requests.push({url,opt});let data={};
   if(url.endsWith('/dynv6/registrations')){
    if(gate)await gate;if(fail){fail=false;throw Error('lost ACK fixture')}
    data={items:JSON.parse(opt.body).domains.map((domain,i)=>{const job={id:'job-'+i,kind:'dynv6_register',scope:domain,status:'queued',result:{}};
     jobs.set(job.id,job);return {...job}}),errors:[]};
   }else if(url.includes('/dynv6-session'))data={status:'valid'};
   else if(url.includes('/domain-jobs/')&&!url.includes('/status?'))data=jobs.get(url.split('/').at(-1));
   else if(url.includes('/domain-jobs?'))data={items:[],total:jobs.size,active_domain_jobs:[],blocked_claim_sources:[]};
   else if(url.endsWith('/dns-credentials'))data={items:credentials};
   else if(url.split('?')[0].endsWith('/mail-domains'))data=domains;
   else if(url.endsWith('/domain-sources')||url.endsWith('/domain-claims'))data={items:[]};
   return {ok:true,status:200,json:async()=>data};
  }});
 vm.runInContext(source+`\nglobalThis.t={state,controlPage,showDynv6SessionDialog,registerControlDynv6,controlJobWatchers,stopControlJobWatchers};
  toast=(text,bad)=>globalThis.notices.push({text,bad});`,Object.assign(context,{notices}));
 const t=context.t;t.state.token='fixture-admin';t.state.tab='control';
 async function tick(){const item=[...timers].find(([,v])=>v.ms===1000||v.ms===2000);assert.ok(item);timers.delete(item[0]);await item[1].fn()}
 return {t,node,requests,jobs,domains,credentials,notices,tick,markup:()=>markup,setGate:g=>gate=g,fail:()=>fail=true};
}
(async()=>{
 const f=fixture();await f.t.controlPage();const original=f.node('#page').innerHTML;
 assert.match(original,/id="dynv6-session-settings"/);assert.match(original,/id="control-bulk-dynv6"/);
 f.t.showDynv6SessionDialog();f.node('#dynv6-session-ref').value='dyn-fixture';f.node('#dynv6-session-cookie').value='fixture-secret-cookie';
 await f.node('#dynv6-session-form').onsubmit({preventDefault(){}});
 const save=f.requests.find(r=>r.url.endsWith('/dynv6-session'));
 assert.equal(save.opt.method,'PUT');assert.equal(JSON.parse(save.opt.body).cookie,'fixture-secret-cookie');
 assert.equal(f.node('#dynv6-session-cookie').value,'');assert.doesNotMatch(f.markup(),/fixture-secret-cookie/);
 assert.equal(f.node('#page').innerHTML,original,'Session save only refreshes list data');
 await f.node('#check-dynv6-session').onclick();
 assert.equal(f.requests.filter(r=>r.url.endsWith('/dynv6-session/check')).length,1);

 let release;f.setGate(new Promise(resolve=>release=resolve));
 const pending=f.t.registerControlDynv6(f.domains,'dyn-fixture');
 assert.equal(f.t.state.controlBusyCounts.size,2,'Lock all rows before dispatch');
 release();await pending;f.setGate(null);
 assert.equal(f.t.controlJobWatchers.size,2);assert.deepEqual([...f.t.state.controlBusyCounts.values()],[1,1]);
 const first=f.jobs.get('job-0');first.status='succeeded';first.result={bound:true};
 const second=f.jobs.get('job-1');second.status='failed';second.error_code='dynv6_session_expired';
 await f.tick();
 assert.equal(f.t.state.controlBusyCounts.size,0);assert.equal(f.t.state.controlBatches.size,0);
 assert.match(f.notices.at(-1).text,/成功 1，待处理 1/);assert.match(f.notices.at(-1).text,/会话已过期/);
 assert.equal(f.node('#page').innerHTML,original,'Completion updates rows without a page reload');

 const lost=fixture();await lost.t.controlPage();lost.fail();
 await assert.rejects(lost.t.registerControlDynv6(lost.domains,'dyn-fixture'),/lost ACK/);
 assert.equal(lost.t.state.controlBusyCounts.size,0);
 await lost.t.registerControlDynv6(lost.domains,'dyn-fixture');
 const posts=lost.requests.filter(r=>r.url.endsWith('/dynv6/registrations'));
 assert.equal(posts[0].opt.headers['Idempotency-Key'],posts[1].opt.headers['Idempotency-Key']);
 lost.t.stopControlJobWatchers();
 console.log('PASS: session save/check and secret clearing; batch row locks, partial completion, list refresh, and lost-ACK idempotency');
})().catch(error=>{console.error(error);process.exitCode=1});
