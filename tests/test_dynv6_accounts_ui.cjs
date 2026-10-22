const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../frontend/index.html'),'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
function fixture(){
 const nodes=new Map(),requests=[],notices=[],credentials=[{id:'legacy-ref',provider:'dynv6',label:'Legacy fixture',session:{configured:true,status:'valid'},login:{email:'',configured:false,status:'manual'}}];
 const domains=[{domain:'fixture.test',enabled:false,dns_provider:'dynv6',dns_credential_ref:'legacy-ref',dns_checks:{}}];
 let markup='',gate=null,fail=false;
 function node(id){if(!nodes.has(id))nodes.set(id,{innerHTML:'',textContent:'',value:'',disabled:false,checked:false,dataset:{},style:{},classList:{toggle(){}},append(){},focus(){},isConnected:true});return nodes.get(id)}
 Object.defineProperty(node('#modal-root'),'innerHTML',{get:()=>markup,set:v=>{markup=v;for(const key of [...nodes.keys()])if(key==='#domain-dialog-bg'||key.startsWith('#dynv6-')||key.startsWith('#save-dynv6')||key.startsWith('#cancel-dynv6'))nodes.delete(key)}});
 const document={body:{classList:{toggle(){}}},querySelector:id=>id==='#domain-dialog-bg'&&!markup?null:node(id),querySelectorAll:selector=>{
   const attr=selector.match(/^\[(data-dynv6-account-(?:edit|refresh))\]$/)?.[1];if(!attr)return [];
   return [...node('#dynv6-accounts-body').innerHTML.matchAll(new RegExp(attr+'="([^"]+)"([^>]*)','g'))].map(match=>{
     const button=node(attr+match[1]);button.dataset[attr==='data-dynv6-account-edit'?'dynv6AccountEdit':'dynv6AccountRefresh']=match[1];button.disabled=match[2].includes('disabled');return button;
   });
 },createElement:()=>({style:{},remove(){}})};
 const context=vm.createContext({document,console,URL,URLSearchParams,localStorage:{getItem:()=>null,removeItem(){}},crypto:{randomUUID:()=>`fixture-${requests.length}`},setTimeout:()=>1,clearTimeout(){},setInterval:()=>1,clearInterval(){},fetch:async(url,opt={})=>{
   requests.push({url,opt});let data={};
   if(url.includes('/dynv6/accounts')&&opt.method){
     if(gate)await gate;
     if(fail){fail=false;return {ok:false,status:409,json:async()=>({detail:{code:'dynv6_login_rejected',message:'fixture login rejected'}})}}
     let row;if(url.endsWith('/refresh')){row=credentials.find(c=>url.includes(c.id));row.login.zone_count=8}
     else{const input=JSON.parse(opt.body);row=opt.method==='PUT'?credentials.find(c=>url.endsWith('/'+c.id)):null;if(!row){row={id:'new-ref',provider:'dynv6'};credentials.push(row)}Object.assign(row,{label:input.label||input.email,session:{configured:true,status:'valid'},login:{email:input.email,configured:true,status:'valid',token_id:'42',token_scope:'all',zone_count:7}})}
     data=row;
   }else if(url.endsWith('/dns-credentials'))data={items:credentials};
   else if(url.endsWith('/mail-domains'))data=domains;
   else if(url.includes('/domain-jobs?'))data={items:[],total:0,active_domain_jobs:[],blocked_claim_sources:[]};
   else if(url.endsWith('/domain-sources')||url.endsWith('/domain-claims'))data={items:[]};
   return {ok:true,status:200,json:async()=>data};
 }});
 vm.runInContext(source+`\nglobalThis.t={state,controlPage,showDynv6AccountsDialog,showDynv6AccountForm,closeModal};toast=(text,bad)=>notices.push({text,bad});`,Object.assign(context,{notices}));
 const t=context.t;t.state.token='fixture-admin';t.state.tab='control';
 return {t,node,requests,notices,credentials,document,markup:()=>markup,setGate:g=>gate=g,fail:()=>fail=true};
}
const event={preventDefault(){}};
function values(f,email='one@example.test',password='fixture-password-private'){f.node('#dynv6-account-label').value='Fixture account';f.node('#dynv6-account-email').value=email;f.node('#dynv6-account-password').value=password}
(async()=>{
 const f=fixture();await f.t.controlPage();const page=f.node('#page').innerHTML;
 f.node('#dynv6-session-settings').onclick();assert.match(f.markup(),/dynv6 账号管理/);assert.match(f.node('#dynv6-accounts-body').innerHTML,/Legacy fixture/);
 f.node('#add-dynv6-account').onclick();assert.match(f.markup(),/type="password"/);assert.doesNotMatch(f.markup(),/<input[^>]+(?:api.?key|token)/i);
 values(f);const input=f.node('#dynv6-account-password');let release;f.setGate(new Promise(resolve=>release=resolve));
 const pending=f.node('#dynv6-account-form').onsubmit(event);await f.node('#dynv6-account-form').onsubmit(event);
 assert.equal(f.node('#save-dynv6-account').disabled,true);assert.equal(f.requests.filter(r=>r.url.endsWith('/dynv6/accounts')&&r.opt.method==='POST').length,1);
 release();await pending;f.setGate(null);assert.equal(input.value,'');assert.match(f.markup(),/dynv6 账号管理/);assert.doesNotMatch(f.markup(),/fixture-password-private/);
 assert.match(f.node('#dynv6-accounts-body').innerHTML,/one@example.test/);assert.equal(f.node('#page').innerHTML,page,'Saving refreshes data without rebuilding the page');
 const legacy=f.credentials[0];f.t.showDynv6AccountForm(legacy);values(f);await f.node('#dynv6-account-form').onsubmit(event);
 const put=f.requests.find(r=>r.url.endsWith('/dynv6/accounts/legacy-ref')&&r.opt.method==='PUT');assert.ok(put);assert.equal(f.t.state.controlDomains[0].dns_credential_ref,'legacy-ref');
 f.t.showDynv6AccountForm(legacy);assert.doesNotMatch(f.markup(),/id="dynv6-account-password"[^>]*required/);values(f,'one@example.test','');await f.node('#dynv6-account-form').onsubmit(event);
 assert.equal(JSON.parse(f.requests.filter(r=>r.opt.method==='PUT').at(-1).opt.body).password,'');
 f.t.showDynv6AccountForm();values(f,'bad@example.test');f.fail();const failed=f.node('#dynv6-account-password');await f.node('#dynv6-account-form').onsubmit(event);
 assert.equal(failed.value,'');assert.equal(f.node('#dynv6-account-message').textContent,'fixture login rejected');assert.equal(f.node('#save-dynv6-account').disabled,false);
 f.t.showDynv6AccountsDialog();const refresh=f.document.querySelectorAll('[data-dynv6-account-refresh]')[0];f.setGate(new Promise(resolve=>release=resolve));
 const syncing=refresh.onclick();await refresh.onclick();assert.equal(refresh.disabled,true);assert.equal(f.document.querySelectorAll('[data-dynv6-account-edit]')[0].disabled,true);
 assert.equal(f.requests.filter(r=>r.url.endsWith('/legacy-ref/refresh')).length,1);release();await syncing;f.setGate(null);
 assert.equal(refresh.disabled,false);assert.match(f.node('#dynv6-accounts-body').innerHTML,/8 个 Zone/);
 f.t.showDynv6AccountForm();values(f);f.setGate(new Promise(resolve=>release=resolve));const detached=f.node('#dynv6-account-password');const late=f.node('#dynv6-account-form').onsubmit(event);
 f.t.closeModal();release();await late;assert.equal(detached.value,'');assert.equal(f.markup(),'','Late result cannot reopen a closed dialog');
 assert.equal(f.node('#page').innerHTML,page);
 console.log('PASS: dynv6 account create/edit, password retention and clearing, duplicate submission locks, account refresh, local list updates, and closed-dialog guards');
})().catch(error=>{console.error(error);process.exitCode=1});
