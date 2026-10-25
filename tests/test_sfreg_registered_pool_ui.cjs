const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const html=fs.readFileSync(path.join(__dirname,'../frontend/index.html'),'utf8');
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
const nodes=new Map(),requests=[];
let markup='',previewRows=[],previewFailure=false,postFailure=false,pendingPreview=null,pendingPost=null;
const document={body:{classList:{toggle(){}}},activeElement:null};
function node(id){
 if(!nodes.has(id))nodes.set(id,{innerHTML:'',value:'',textContent:'',checked:false,disabled:false,dataset:{},style:{},
  classList:{toggle(){}},append(){},focus(){document.activeElement=this},isConnected:true});
 return nodes.get(id);
}
Object.defineProperty(node('#modal-root'),'innerHTML',{get:()=>markup,set(value){
 markup=value;
 for(const id of [...nodes.keys()])if(id==='#domain-dialog-bg'||id.startsWith('#source-')||id.startsWith('[data-source-select]'))nodes.delete(id);
 // Match browser defaults so assertions exercise the actual selected filters.
 for(const match of value.matchAll(/<select id="([^"]+)"[^>]*>([\s\S]*?)<\/select>/g)){
  const options=[...match[2].matchAll(/<option(?: value="([^"]*)")?([^>]*)>([^<]*)<\/option>/g)];
  const selected=options.find(option=>/\bselected\b/.test(option[2]))||options[0];
  if(selected)node('#'+match[1]).value=selected[1]??selected[3];
 }
 for(const match of value.matchAll(/<input id="([^"]+)"[^>]*value="([^"]*)"/g))node('#'+match[1]).value=match[2];
}});
document.querySelector=id=>id==='#domain-dialog-bg'&&!markup?null:node(id);
document.querySelectorAll=selector=>{
 if(selector!=='[data-source-select]')return [];
 return [...node('#source-preview-body').innerHTML.matchAll(/data-source-select="(\d+)"/g)].map(match=>{
  const box=node(selector+':'+match[1]);box.dataset.sourceSelect=match[1];return box;
 });
};
document.createElement=()=>({style:{},remove(){}});
const context=vm.createContext({document,localStorage:{getItem:()=>null},console,URL,URLSearchParams,
 crypto:{randomUUID:()=> 'fixture-'+requests.length},
 setTimeout:()=>1,clearTimeout(){},setInterval:()=>1,clearInterval(){},
 fetch:async(url,opt={})=>{
  requests.push({url,opt});
  if(url.includes('/candidates')){
   const captured=previewRows,wait=pendingPreview;
   if(wait)await wait;
   if(previewFailure){previewFailure=false;return {ok:false,status:502,json:async()=>({detail:'fixture unavailable'})}}
   return {ok:true,status:200,json:async()=>({items:captured,total:captured.length,allocation:'none'})};
  }
  if(opt.method==='POST'){
   if(pendingPost)await pendingPost;
   if(postFailure){postFailure=false;throw Error('fixture lost ACK')}
  }
  const data=url.split('?')[0].endsWith('/mail-domains')?[]:url.includes('/domain-jobs?')?{items:[],total:0,blocked_claim_sources:[]}:
   url.endsWith('/domain-sources')||url.endsWith('/dns-credentials')?{items:[]}:{id:'fixture-job',status:'queued'};
  return {ok:true,status:200,json:async()=>data};
 }
});
vm.runInContext(script+'\nglobalThis.t={state,showSourceCandidates,showSourceClaimDialog,closeModal};',context);
const t=context.t;t.state.token='fixture-session';t.state.tab='control';
const source={id:'sfreg-fixture',name:'SFREG fixture',source_type:'sfreg_mx',enabled:true};
const event={preventDefault(){}};
const posts=()=>requests.filter(r=>r.opt.method==='POST');
function select(index,checked=true){
 const box=node('[data-source-select]:'+index);box.checked=checked;box.onchange();
}
function selectAll(checked=true){const box=node('#source-preview-all');box.checked=checked;box.onchange()}
const row=(id,domain='registered.test',status='registered')=>({external_id:String(id),domain,status});
(async()=>{
 previewRows=[row(5330),row(5331,'second.test'),row('invalid-id','unselectable.test')];
 await t.showSourceCandidates(source);
 let query=new URL(requests.at(-1).url,'https://fixture.test').searchParams;
 assert.equal(query.get('status'),'registered');assert.equal(query.get('sync_provider'),'none');assert.equal(query.get('count'),'10');
 assert.match(node('#source-preview-body').innerHTML,/registered.test/);
 assert.equal(node('#claim-source-preview').disabled,true);assert.equal(posts().length,0,'Preview must never allocate');
 assert.equal(node('#source-preview-all').disabled,false);
 assert.equal(node('#source-preview-all').checked,false);assert.equal(node('#source-preview-all').indeterminate,false);
 select(0);assert.equal(node('#source-preview-all').indeterminate,true);
 selectAll();assert.equal(node('#source-preview-selected').textContent,'已选 2 个');
 assert.equal(node('#source-preview-all').checked,true);assert.equal(node('#source-preview-all').indeterminate,false);
 assert.equal(document.querySelectorAll('[data-source-select]').length,2,'Select all must exclude rows without a claimable numeric ID');
 assert.ok(document.querySelectorAll('[data-source-select]').every(box=>box.checked));
 select(1,false);assert.equal(node('#source-preview-all').checked,false);assert.equal(node('#source-preview-all').indeterminate,true);
 selectAll(false);assert.equal(node('#source-preview-selected').textContent,'已选 0 个');
 assert.ok(document.querySelectorAll('[data-source-select]').every(box=>!box.checked));
 selectAll();assert.equal(node('#source-preview-selected').textContent,'已选 2 个');
 node('#claim-source-preview').onclick();
 assert.match(markup,/registered.test/);assert.match(markup,/second.test/);assert.match(markup,/readonly/);
 assert.doesNotMatch(markup,/id="source-claim-status"/,'Selection confirmation must freeze the preview filters');
 const expected={count:2,status:'registered',sync_provider:'none',external_ids:['5330','5331']};
 postFailure=true;await node('#source-claim-form').onsubmit(event);
 assert.match(node('#source-claim-msg').textContent,/lost ACK/);
 const key=posts().at(-1).opt.headers['Idempotency-Key'];
 assert.deepEqual(JSON.parse(posts().at(-1).opt.body),expected);
 await node('#source-claim-form').onsubmit(event);
 assert.equal(posts().at(-1).opt.headers['Idempotency-Key'],key);assert.equal(markup,'');

 await t.showSourceCandidates(source);select(0);
 previewRows=[];node('#source-preview-status').value='sync_failed';node('#source-preview-provider').value='all';
 await node('#source-preview-status').onchange();
 assert.equal(node('#source-preview-selected').textContent,'已选 0 个');assert.equal(node('#claim-source-preview').disabled,true);
 assert.match(node('#source-preview-body').innerHTML,/没有未领取域名/);
 assert.equal(node('#source-preview-all').disabled,true);
 assert.equal(node('#source-preview-all').checked,false);assert.equal(node('#source-preview-all').indeterminate,false);
 query=new URL(requests.at(-1).url,'https://fixture.test').searchParams;
 assert.equal(query.get('status'),'sync_failed');assert.equal(query.get('sync_provider'),'all');
 previewRows=[row(5332,'failed.test','sync_failed')];await node('#reload-source-preview').onclick();select(0);
 node('#source-preview-count').value='200';previewFailure=true;await node('#source-preview-count').onchange();
 assert.equal(node('#claim-source-preview').disabled,true);assert.equal(node('#source-preview-body').innerHTML,'');
 assert.equal(node('#source-preview-summary').textContent,'fixture unavailable');
 assert.equal(node('#source-preview-all').disabled,true);

 previewRows=[row(1,'old.test')];let releasePreview;pendingPreview=new Promise(resolve=>releasePreview=resolve);
 const old=node('#reload-source-preview').onclick();pendingPreview=null;
 assert.equal(node('#source-preview-all').disabled,true,'Select all must remain disabled while loading');
 previewRows=[row(2,'new.test')];node('#source-preview-status').value='registered';
 await node('#source-preview-status').onchange();releasePreview();await old;
 assert.match(node('#source-preview-body').innerHTML,/new.test/);assert.doesNotMatch(node('#source-preview-body').innerHTML,/old.test/);
 select(0);
 node('#source-preview-provider').value='digitalplat_dns';await node('#source-preview-provider').onchange();
 assert.equal(node('#source-preview-status').value,'synced');
 assert.doesNotMatch(node('#source-preview-body').innerHTML,/data-source-select/);
 assert.equal(node('#claim-source-preview').disabled,true);
 assert.equal(node('#source-preview-all').disabled,true,'MX pool does not support selecting IDs');
 assert.match(node('#source-preview-summary').textContent,/独立 DNS 凭据/);
 node('#cancel-source-preview').onclick();assert.equal(markup,'');
 t.showSourceClaimDialog(source);
 assert.equal(node('#source-claim-provider').value,'digitalplat_dns');
 node('#source-claim-count').value='1';await node('#source-claim-form').onsubmit(event);
 assert.deepEqual(JSON.parse(posts().at(-1).opt.body),{count:1,status:'synced',sync_provider:'digitalplat_dns'});

 t.state.sourcePools={};previewRows=[row(3,'blocked.test')];
 const before=posts().length;await t.showSourceCandidates({...source,claim_blocked:true});select(0);
 assert.equal(node('#claim-source-preview').disabled,true);
 node('#claim-source-preview').onclick();assert.match(markup,/预览候选/);
 t.showSourceClaimDialog({...source,claim_blocked:true});
 await node('#source-claim-form').onsubmit(event);
 assert.equal(posts().length,before);assert.match(node('#source-claim-msg').textContent,/核对已有领取任务/);

 let finishPreview;pendingPreview=new Promise(resolve=>finishPreview=resolve);
 const closing=t.showSourceCandidates(source);t.closeModal();t.showSourceClaimDialog(source);
 const currentMarkup=markup;finishPreview();await closing;pendingPreview=null;
 assert.equal(markup,currentMarkup,'A late preview must not replace a newer dialog');
 let finishPost;pendingPost=new Promise(resolve=>finishPost=resolve);
 const saving=node('#source-claim-form').onsubmit(event),beforeDuplicate=posts().length;
 await node('#source-claim-form').onsubmit(event);assert.equal(posts().length,beforeDuplicate);
 t.closeModal();await t.showSourceCandidates(source);finishPost();await saving;pendingPost=null;
 assert.match(markup,/预览候选/,'A completed claim must not close a newer dialog');
 assert.doesNotMatch(node('#source-preview-body').innerHTML,/script/);
 console.log('PASS: registered preview, filters, select-all/clear/mixed state, excluded IDs, count, selection confirmation, stable retry key, empty/error/loading state, cleared selection, stale responses, MX compatibility, blocked claims and duplicate submit');
})().catch(error=>{console.error(error);process.exitCode=1});
