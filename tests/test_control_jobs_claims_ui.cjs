const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const html=fs.readFileSync(path.join(__dirname,'../frontend/index.html'),'utf8'),source=html.match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(source);
const nodes=new Map(),requests=[],timers=new Map();let nextTimer=0,deferred=null,detailDeferred=null,failure=false;
const jobs=Array.from({length:154},(_,i)=>({id:'job-'+i,kind:i%2?'dns_apply':'dns_validate',scope:'sample-'+i+'.test',status:i%2?'succeeded':'failed',step:'recorded',created_at:1000+i,result:{}}));
const document={body:{classList:{toggle(){}}},activeElement:null};
function node(id){if(!nodes.has(id))nodes.set(id,{innerHTML:'',value:'',textContent:'',disabled:false,dataset:{},style:{},classList:{toggle(){}},append(){},focus(){},isConnected:true,querySelector:node,querySelectorAll:()=>[]});return nodes.get(id)}
const root=node('#modal-root');let markup='';Object.defineProperty(root,'innerHTML',{get(){return markup},set(value){markup=value;nodes.delete('#domain-dialog-bg')}});
document.querySelector=id=>id==='#domain-dialog-bg'&&!markup?null:node(id);
document.querySelectorAll=selector=>{
 const attribute=selector.match(/^\[data-([\w-]+)\]$/)?.[1];if(!attribute)return [];
 const camel=attribute.replace(/-([a-z])/g,(_,c)=>c.toUpperCase());
 const content=node('#control-task-body').innerHTML+node('#control-task-pages').innerHTML;
 return [...content.matchAll(new RegExp('data-'+attribute+'="([^"]+)"','g'))].map(m=>{const b=node(selector+':'+m[1]);b.dataset[camel]=m[1];return b});
};
document.createElement=()=>({style:{},remove(){}});
const context=vm.createContext({document,localStorage:{getItem:()=>null},console,URL,crypto:{randomUUID:()=> 'fixture-'+requests.length},
 setTimeout:fn=>{timers.set(++nextTimer,fn);return nextTimer},clearTimeout:id=>timers.delete(id),setInterval:()=>1,clearInterval(){},
 fetch:async(url,opt={})=>{
  requests.push({url,opt});const u=new URL(url,'https://fixture.test');
  if(opt.method==='POST'&&failure){failure=false;throw Error('fixture lost ACK')}
  if(u.pathname.endsWith('/domain-jobs')){
   const captured=deferred;if(captured)await captured;
   const q=(u.searchParams.get('q')||'').trim().toLowerCase(),status=u.searchParams.get('status')||'';
   const filtered=jobs.filter(j=>(!status||j.status===status)&&(!q||[j.id,j.kind,j.scope,j.status].some(v=>v.toLowerCase().includes(q))));
   const offset=Number(u.searchParams.get('offset')||0),limit=Number(u.searchParams.get('limit')||100);
   return {ok:true,status:200,json:async()=>({items:filtered.slice(offset,offset+limit),total:filtered.length,status_counts:{},blocked_claim_sources:[]})};
  }
  if(u.pathname.includes('/domain-jobs/')&&detailDeferred)await detailDeferred;
  const data=u.pathname.includes('/domain-jobs/')?jobs.find(j=>u.pathname.endsWith('/'+j.id)):
   u.pathname.endsWith('/mail-domains')?[]:u.pathname.endsWith('/domain-sources')||u.pathname.endsWith('/dns-credentials')?{items:[]}:{id:'new-job',status:'queued'};
  return {ok:true,status:200,json:async()=>data};
 }
});
vm.runInContext(source+'\nglobalThis.t={state,showControlTasks,showSourceClaimDialog,closeModal,controlPage};',context);
const t=context.t;t.state.token='fixture-session';t.state.tab='control';const event={preventDefault(){}};
const postClaims=()=>requests.filter(r=>r.opt.method==='POST'&&r.url.endsWith('/claim'));
(async()=>{
 await t.controlPage();assert.match(node('#page').innerHTML,/id="open-control-tasks"/);assert.doesNotMatch(node('#page').innerHTML,/id="control-task-body"/);
 await t.showControlTasks();assert.match(markup,/持久任务 · 操作记录/);assert.match(node('#control-task-summary').textContent,/共 154 条.*第 1 \/ 8 页/);
 assert.equal((node('#control-task-body').innerHTML.match(/<tr>/g)||[]).length,20);
 await node('#control-task-next').onclick();assert.equal(t.state.controlTasks.page,2);assert.match(requests.at(-1).url,/offset=20/);
 node('#control-task-jump').value='999';await node('#control-task-jump-btn').onclick();assert.equal(t.state.controlTasks.page,8);assert.match(node('#control-task-summary').textContent,/第 8 \/ 8 页/);assert.equal(node('#control-task-next').disabled,true);
 node('#control-task-jump').value='-2';await node('#control-task-jump-btn').onclick();assert.equal(t.state.controlTasks.page,1);
 await node('#control-task-size').onchange({target:{value:'50'}});assert.equal(t.state.controlTasks.pageSize,50);
 await node('#control-task-status').onchange({target:{value:'failed'}});assert.match(node('#control-task-summary').textContent,/共 77 条/);
 node('#control-task-search').oninput({target:{value:'sample-153'}});await node('#control-task-search').onkeydown({key:'Enter'});
 assert.match(node('#control-task-summary').textContent,/共 0 条/);assert.match(node('#control-task-body').innerHTML,/没有匹配的任务/);
 await node('#clear-control-task-search').onclick();node('#control-task-search').oninput({target:{value:'sample-153'}});await node('#control-task-search').onkeydown({key:'Enter'});
 assert.match(node('#control-task-body').innerHTML,/sample-153.test/);
 await node('[data-control-job]:job-153').onclick();assert.match(markup,/任务详情/);assert.match(markup,/sample-153.test/);
 await node('#back-control-tasks').onclick();assert.match(markup,/持久任务 · 操作记录/);assert.equal(t.state.controlTasks.query,'sample-153');
 let releaseDetail;detailDeferred=new Promise(resolve=>releaseDetail=resolve);const oldDetail=node('[data-control-job]:job-153').onclick();
 await node('#clear-control-task-search').onclick();releaseDetail();await oldDetail;detailDeferred=null;
 assert.match(markup,/持久任务 · 操作记录/,'Late detail response must not replace the list after a filter or page change');
 let release;deferred=new Promise(resolve=>release=resolve);const old=node('#reload-control-tasks').onclick();
 deferred=null;node('#control-task-search').oninput({target:{value:'no-match'}});await node('#control-task-search').onkeydown({key:'Enter'});release();await old;
 assert.match(node('#control-task-summary').textContent,/共 0 条/,'Late responses must not overwrite newer filters');
 t.closeModal();
 const sfreg={id:'source-sfreg',name:'SFREG fixture',source_type:'sfreg_mx'};
 t.showSourceClaimDialog(sfreg);assert.match(markup,/领取数量/);assert.match(markup,/max="200"/);
 node('#source-claim-count').value='0';await node('#source-claim-form').onsubmit(event);assert.equal(postClaims().length,0);assert.match(node('#source-claim-msg').textContent,/1–200/);
 node('#source-claim-count').value='3';failure=true;await node('#source-claim-form').onsubmit(event);assert.match(node('#source-claim-msg').textContent,/lost ACK/);assert.ok(markup);
 const key=postClaims().at(-1).opt.headers['Idempotency-Key'];await node('#source-claim-form').onsubmit(event);
 assert.equal(postClaims().at(-1).opt.headers['Idempotency-Key'],key);assert.equal(JSON.parse(postClaims().at(-1).opt.body).count,3);assert.equal(markup,'');
 t.showSourceClaimDialog(sfreg);assert.match(markup,/value="3"/);t.closeModal();
 t.showSourceClaimDialog({id:'source-legacy',name:'Legacy fixture',source_type:'legacy_digitalplat_pool'});
 node('#source-claim-count').value='2';node('#source-claim-ids').value='id-1,id-1';const before=postClaims().length;await node('#source-claim-form').onsubmit(event);assert.equal(postClaims().length,before);
 node('#source-claim-ids').value='id-1\nid-2';await node('#source-claim-form').onsubmit(event);assert.deepEqual(JSON.parse(postClaims().at(-1).opt.body),{count:2,external_ids:['id-1','id-2']});
 assert.equal(postClaims().at(-1).opt.headers['X-API-Key'],'fixture-session');
 console.log('PASS: server-paged task dialog, search/status/jump/empty/details/back and stale fencing; claim quantities, legacy IDs, remembered count and stable retry key');
})().catch(e=>{console.error(e);process.exitCode=1});
