const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const html=fs.readFileSync(path.join(__dirname,'../frontend/index.html'),'utf8');
const source=html.match(/<script>([\s\S]*?)<\/script>/)[1];
const nodes=new Map(),requests=[];
let fail=false,pending=null;
const document={body:{classList:{toggle(){}}},activeElement:null};
function node(id){
 if(!nodes.has(id))nodes.set(id,{innerHTML:'',textContent:'',value:'',checked:false,disabled:false,required:false,readOnly:false,dataset:{},classes:new Map(),classList:{toggle(name,value){node(id).classes.set(name,value)}},append(){},focus(){document.activeElement=this},isConnected:true});
 return nodes.get(id);
}
const root=node('#modal-root');let markup='';
Object.defineProperty(root,'innerHTML',{get(){return markup},set(value){markup=value;nodes.delete('#domain-dialog-bg');for(const id of ['source-label','source-kind','source-base','source-client','source-secret','credential-label','credential-provider','credential-domain','credential-base','credential-secret','control-create-msg','save-control-create','cancel-control-create'])nodes.delete('#'+id)}});
document.querySelector=id=>id==='#domain-dialog-bg'&&!markup?null:node(id);
document.querySelectorAll=()=>[];
document.createElement=()=>({style:{},remove(){}});
const context=vm.createContext({document,localStorage:{getItem:()=>null},console,
 setTimeout:()=>1,clearTimeout(){},setInterval:()=>1,clearInterval(){},
 fetch:async(url,opt={})=>{
  requests.push({url,opt});
  if(opt.method==='POST'&&pending)await pending;
  if(opt.method==='POST'&&fail){fail=false;return {ok:false,status:400,json:async()=>({detail:'fixture rejected'})}}
  const data=url.endsWith('/mail-domains')?[]:url.includes('/domain-jobs?')?{items:[],total:0}:url.endsWith('/domain-sources')||url.endsWith('/dns-credentials')?{items:[]}:{};
  return {ok:true,status:200,json:async()=>data};
 }
});
vm.runInContext(source+'\nglobalThis.t={state,controlPage,closeModal};',context);
const t=context.t;t.state.token='fixture-session';t.state.tab='control';
const event={preventDefault(){}};
const posts=path=>requests.filter(r=>r.url==='/api/v1'+path&&r.opt.method==='POST');
function sourceValues(type='sfreg_mx'){
 node('#source-label').value=' fixture source ';node('#source-kind').value=type;
 node('#source-base').value='https://source.example.test';node('#source-client').value='mail-stack';node('#source-secret').value='fixture-source-secret';
 if(type==='cloudflare_import')node('#source-kind').onchange();
}
function credentialValues(provider='cloudflare'){
 node('#credential-label').value=' fixture credential ';node('#credential-provider').value=provider;
 node('#credential-domain').value='';node('#credential-base').value='https://dns.example.test/api/v1';node('#credential-secret').value='fixture-credential-secret';
 node('#credential-provider').onchange();
}
(async()=>{
 await t.controlPage();
 assert.doesNotMatch(node('#page').innerHTML,/id="(?:source-create-form|credential-create-form)"/);
 assert.match(node('#page').innerHTML,/① 已配置的域名来源/);
 assert.match(node('#page').innerHTML,/领取结果与 DNS 绑定、变更/);
 assert.match(node('#page').innerHTML,/id="open-control-tasks"/);assert.doesNotMatch(node('#page').innerHTML,/id="control-task-body"/);
 node('#add-domain-source').onclick();
 assert.match(markup,/role="dialog" aria-modal="true"/);assert.match(markup,/添加域名来源/);
 assert.match(markup,/form="source-create-form"/);
 node('#source-base').value='https://custom.example.test';node('#source-kind').value='cloudflare_import';node('#source-kind').onchange();
 assert.equal(node('#source-base').value,'https://api.cloudflare.com/client/v4');assert.equal(node('#source-base').readOnly,true);
 node('#source-kind').value='sfreg_mx';node('#source-kind').onchange();
 assert.equal(node('#source-base').value,'https://custom.example.test');assert.equal(node('#source-base').readOnly,false);
 node('#cancel-control-create').onclick();assert.equal(markup,'');assert.equal(posts('/domain-sources').length,0);
 for(const [type,field] of [['sfreg_mx','api_key'],['legacy_digitalplat_pool','admin_key'],['cloudflare_import','api_token']]){
  node('#add-domain-source').onclick();sourceValues(type);
  const secret=node('#source-secret');await node('#source-create-form').onsubmit(event);
  const request=posts('/domain-sources').at(-1),body=JSON.parse(request.opt.body);
  assert.equal(body.source_type,type);if(type==='cloudflare_import')assert.equal(body.base_url,'https://api.cloudflare.com/client/v4');assert.equal(body.secret[field],'fixture-source-secret');assert.deepEqual(Object.keys(body.secret),[field]);assert.equal(body.name,'fixture source');
  assert.equal(secret.value,'');assert.equal(markup,'');assert.equal(request.opt.headers['X-API-Key'],'fixture-session');
 }
 node('#add-domain-source').onclick();sourceValues();fail=true;
 await node('#source-create-form').onsubmit(event);
 assert.equal(node('#control-create-msg').textContent,'fixture rejected');assert.equal(node('#save-control-create').disabled,false);
 assert.equal(node('#source-secret').value,'fixture-source-secret');assert.ok(markup);
 t.closeModal();
 node('#add-dns-credential').onclick();credentialValues();
 assert.match(markup,/添加 DNS 凭据/);assert.match(markup,/form="credential-create-form"/);
 assert.equal(node('#credential-domain').required,false);assert.equal(node('#credential-base').disabled,true);
 assert.equal(node('#credential-base-field').classes.get('hidden'),true);
 const cfSecret=node('#credential-secret');await node('#credential-create-form').onsubmit(event);
 const cf=JSON.parse(posts('/dns-credentials').at(-1).opt.body);
 assert.equal(cf.provider,'cloudflare');assert.equal(cf.domain,null);assert.deepEqual(cf.secret,{api_token:'fixture-credential-secret'});
 assert.equal(cfSecret.value,'');assert.equal(markup,'');
 node('#add-dns-credential').onclick();credentialValues('digitalplat');
 assert.equal(node('#credential-domain').required,true);assert.equal(node('#credential-base').required,true);assert.equal(node('#credential-base').disabled,false);
 const before=posts('/dns-credentials').length;await node('#credential-create-form').onsubmit(event);
 assert.equal(posts('/dns-credentials').length,before);assert.equal(node('#control-create-msg').textContent,'DigitalPlat 凭据必须绑定具体域名');
 node('#credential-domain').value=' domain.example.test ';const dpSecret=node('#credential-secret');
 await node('#credential-create-form').onsubmit(event);
 const dp=JSON.parse(posts('/dns-credentials').at(-1).opt.body);
 assert.equal(dp.domain,'domain.example.test');assert.equal(dp.secret.api_base,'https://dns.example.test/api/v1');assert.equal(dpSecret.value,'');assert.equal(markup,'');
 node('#add-domain-source').onclick();sourceValues();
 let release;pending=new Promise(resolve=>{release=resolve});
 const oldSecret=node('#source-secret'),oldForm=node('#source-create-form'),beforePosts=posts('/domain-sources').length;
 const saving=oldForm.onsubmit(event);await oldForm.onsubmit(event);
 assert.equal(posts('/domain-sources').length,beforePosts+1);assert.equal(node('#save-control-create').disabled,true);
 t.closeModal();node('#add-dns-credential').onclick();credentialValues();const newSecret=node('#credential-secret');
 release();await saving;pending=null;
 assert.equal(oldSecret.value,'');assert.equal(newSecret.value,'fixture-credential-secret');assert.match(markup,/添加 DNS 凭据/,'A completed save must not close a newer dialog');
 node('#domain-dialog-bg').onkeydown({key:'Escape',preventDefault(){}});assert.equal(markup,'');
 assert.doesNotMatch(node('#page').innerHTML,/fixture-source-secret|fixture-credential-secret/);
 console.log('PASS: source/credential centered dialogs, cancel/Escape, source secret variants, URL switching, provider validation, success clearing/refresh, failure retention, duplicate guard and stale-save isolation');
})().catch(e=>{console.error(e);process.exitCode=1});
