const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {fixture}=require('./test_dns_batch_performance_ui.cjs');
const script=fs.readFileSync(require('node:path').join(__dirname,'../frontend/index.html'),'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];

function navigation(saved,blocked=false,fetch){
  const storage=new Map([['mail_navigation',saved]]),nodes=new Map();
  const node=id=>{if(!nodes.has(id))nodes.set(id,{innerHTML:'',classList:{toggle(){}},dataset:{}});return nodes.get(id)};
  const context=vm.createContext({
    document:{querySelector:node,querySelectorAll:()=>[],body:{classList:{toggle(){}}}},
    localStorage:{getItem:key=>storage.get(key)||null,setItem:(key,value)=>{if(blocked)throw Error('QuotaExceededError');storage.set(key,value)}},
    setTimeout:()=>1,clearTimeout(){},setInterval:()=>1,clearInterval(){},console,fetch,
  });
  vm.runInContext(script+'\nglobalThis.test={state,saveNavigation,claimStatusLabel,keysPage,webhooksPage,inboxPage,pageCache,api};',context);
  return {...context.test,storage,node};
}

(async()=>{
  for(const saved of ['{bad json','null','[]','{"tab":"__proto__","controlDns":{"status":"invalid","page":-10,"pageSize":999}}']){
    const {state}=navigation(saved);
    assert.equal(state.tab,'inbox');assert.equal(state.controlDns.status,'pending');
    assert.equal(state.controlDns.page,1);assert.equal(state.controlDns.pageSize,20);
  }
  const restored=navigation(JSON.stringify({tab:'control',controlDns:{status:'ready',query:'example.test',provider:'dynv6',page:3,pageSize:50}}));
  assert.equal(restored.state.tab,'control');assert.equal(restored.state.controlDns.status,'ready');
  assert.equal(restored.state.controlDns.query,'example.test');assert.equal(restored.state.controlDns.page,3);
  assert.equal(restored.state.controlDns.provider,'dynv6');assert.equal(restored.state.controlDns.pageSize,50);
  restored.state.controlDns.status='processing';restored.saveNavigation();
  assert.equal(navigation(restored.storage.get('mail_navigation')).state.controlDns.status,'processing');
  restored.state.tab='send';restored.saveNavigation();
  assert.equal(navigation(restored.storage.get('mail_navigation')).state.tab,'send');
  assert.doesNotThrow(()=>navigation('{}',true).saveNavigation());
  assert.equal(restored.claimStatusLabel({status:'imported',upstream_status:'reserved'}),'已导入 · 已预留');
  assert.equal(restored.claimStatusLabel({status:'claimed',upstream_status:'claimed'}),'已领取');
  assert.equal(restored.claimStatusLabel({status:'new_upstream_state'}),'new_upstream_state');

  for(const [tab,loader,data] of [['keys','keysPage',[]],['webhooks','webhooksPage',[]],['inbox','inboxPage',{items:[],total:0}]]){
    let release;
    const stale=navigation(JSON.stringify({tab}),false,()=>new Promise(resolve=>release=resolve));
    stale.state.token='fixture-session';
    const pending=stale[loader](true);
    stale.state.tab='security';stale.node('#page').innerHTML='<h2>安全与文档</h2>';
    release({ok:true,status:200,json:async()=>data});await pending;
    assert.equal(stale.node('#page').innerHTML,'<h2>安全与文档</h2>',`${tab}: a late response must not overwrite the next tab`);
  }

  const changed=navigation('{}',false,async()=>({ok:true,status:200,json:async()=>({})}));
  for(const tab of ['domains','control','send'])changed.pageCache.set(tab,{ready:true,dirty:false});
  await changed.api('/mail-domains/example.test');
  assert.equal(changed.pageCache.get('control').dirty,false,'Reads preserve the cache');
  await changed.api('/mail-domains/example.test',{method:'PATCH'});
  assert.equal(changed.pageCache.get('control').dirty,true,'Domain writes invalidate cached DNS data');
  assert.equal(changed.pageCache.get('domains').dirty,true);
  assert.equal(changed.pageCache.get('send').dirty,false,'Domain writes preserve a cached mail draft');

  const f=fixture(23);await f.t.controlPage();
  f.t.lockControlDomain(f.domains[0].domain);f.t.renderControlUnifiedResults();
  f.node('#control-dns-all').checked=true;f.node('#control-dns-all').onchange();
  assert.equal(f.t.state.controlSelection.size,19);
  assert.equal(f.t.state.controlSelection.has(f.domains[0].domain),false);
  assert.equal(f.node('#control-dns-all').checked,true);
  f.t.state.controlDns.page=2;f.t.renderControlUnifiedResults();
  f.node('#control-dns-all').checked=true;f.node('#control-dns-all').onchange();
  assert.equal(f.t.state.controlSelection.size,22,'Cross-page selection excludes the locked row');
  f.t.state.controlDns.page=1;f.t.renderControlUnifiedResults();
  f.node('#control-dns-all').checked=false;f.node('#control-dns-all').onchange();
  assert.equal(f.t.state.controlSelection.size,3,'Deselect affects only the current page');
  f.t.unlockControlDomain(f.domains[0].domain);f.t.renderControlUnifiedResults();
  assert.equal(f.t.state.controlSelection.has(f.domains[0].domain),false,'Unlocking never selects a row implicitly');
  f.domains.forEach(d=>f.t.lockControlDomain(d.domain));f.t.renderControlUnifiedResults();
  assert.equal(f.node('#control-dns-all').disabled,true);
  f.node('#control-dns-all').checked=true;f.node('#control-dns-all').onchange();
  assert.equal(f.t.state.controlSelection.size,3,'Even a direct event cannot select locked rows');
  console.log('PASS: navigation persistence/storage fallback and stale-response isolation; Chinese status; locked and cross-page selection, deselect, unlock and fully locked pages');
})().catch(error=>{console.error(error);process.exitCode=1});
