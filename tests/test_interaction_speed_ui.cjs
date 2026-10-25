const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const script=fs.readFileSync(path.join(__dirname,'../frontend/index.html'),'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const tick=()=>new Promise(setImmediate);
function fixture(){
  const nodes=new Map(),requests=[],timers=new Map(),notices=[];
  let nextTimer=0;
  function fresh(id=''){
    const node={id,html:'',writes:0,textContent:'',value:'',disabled:false,checked:false,dataset:{},scrollTop:0,scrollLeft:0,
      classList:{toggle(){}},children:[],setAttribute(name,value){this[name]=value},focus(){document.activeElement=this},
      getClientRects:()=>[{}],querySelectorAll:()=>[],querySelector(selector){return selector==='h2'&&this.html.includes('<h2>')?{}:null},
      append(child){this.children.push(child)},replaceWith(other){nodes.set('#page',other)},remove(){nodes.delete('#'+id)}};
    Object.defineProperty(node,'innerHTML',{get:()=>node.html,set(value){
      node.writes++;node.html=value;
      for(const [key,child] of nodes)if(child.parent===node)nodes.delete(key);
      for(const match of value.matchAll(/<[^>]*\bid="([^"]+)"[^>]*>/g)){
        const child=fresh(match[1]);child.parent=node;child.value=match[0].match(/\bvalue="([^"]*)"/)?.[1]||'';
        child.disabled=/\sdisabled(?:[\s>])/.test(match[0]);nodes.set('#'+child.id,child);
      }
    }});
    return node;
  }
  for(const id of ['page','modal-root','toast-root','top-title','app'])nodes.set('#'+id,fresh(id));
  const document={hidden:false,activeElement:null,body:{classList:{toggle(){}}},
    querySelector:selector=>nodes.get(selector)||null,querySelectorAll:()=>[],createElement:()=>fresh()};
  const context=vm.createContext({console,document,AbortController,
    localStorage:{getItem:()=>null,setItem(){},removeItem(){}},
    setTimeout:(fn,ms)=>{timers.set(++nextTimer,{fn,ms});return nextTimer},clearTimeout:id=>timers.delete(id),setInterval:()=>1,clearInterval(){},
    fetch:(url,opt={})=>new Promise((resolve,reject)=>{
      // Deliberately ignore abort: late network completions must also be fenced.
      const request={url,opt,settled:false,reply(data,status=200){this.settled=true;resolve({ok:status<400,status,json:async()=>data})},reject};
      requests.push(request);
    })});
  vm.runInContext(script+'\nglobalThis.test={state,api,ensureDomains,invalidateAvailableDomains,readProjects,inboxPage,renderInboxResults,renderPage,sendPage,createKey,editKey,showWebhookDeliveries,closeModal,claimForDomain,controlCredential,resetPageCache};',context);
  context.notices=notices;vm.runInContext('toast=(text,bad)=>notices.push({text,bad});',context);
  context.test.state.token='session-a';
  const pending=suffix=>{const item=requests.find(r=>!r.settled&&r.url.endsWith(suffix));assert.ok(item,'missing request '+suffix);return item};
  return {t:context.test,nodes,node:key=>nodes.get(key),requests,timers,document,notices,pending,context};
}
const message=subject=>({id:1,subject,sender:'sender@example.test',envelope_recipient:'inbox@example.test',received_at:1792740000});
async function loadInbox(f){
  const work=f.t.renderPage();await tick();f.pending('/domains').reply([{domain:'example.test'}]);
  f.pending('&meta=1').reply({items:[message('Initial')],total:80});await work;await tick();
}
(async()=>{
  const fast=fixture(),opening=fast.t.renderPage();await tick();
  assert.ok(fast.node('#mail-search'),'search mounts while auxiliary domains are still pending');
  assert.equal(fast.requests.length,2,'mail and domains start independently');
  fast.pending('&meta=1').reply({items:[message('Mailbox ready')],total:1});await opening;
  assert.match(fast.node('#mail-table-body').innerHTML,/Mailbox ready/);
  assert.equal(fast.pending('/domains').settled,false,'slow domains never block the mail list');
  fast.pending('/domains').reply([{domain:'example.test'}]);await tick();
  assert.equal(fast.node('#inbox-domain-count').textContent,'1');

  const latest=fixture();await loadInbox(latest);
  latest.t.state.query='old';const old=latest.t.inboxPage(true),oldRequest=latest.pending('&meta=1');
  latest.t.state.query='new';const newest=latest.t.inboxPage(true),newRequest=latest.requests.at(-1);
  assert.equal(oldRequest.opt.signal.aborted,true,'obsolete reads are cancelled');
  const duplicate=latest.t.inboxPage(true);
  assert.equal(duplicate,newest,'same-view clicks share the pending promise');
  newRequest.reply({items:[message('Latest result')],total:1});await newest;
  oldRequest.reply({items:[message('Obsolete result')],total:1});await old;
  assert.match(latest.node('#mail-table-body').innerHTML,/Latest result/);
  assert.doesNotMatch(latest.node('#mail-table-body').innerHTML,/Obsolete/);

  const paging=fixture();await loadInbox(paging);
  paging.t.state.page=2;const second=paging.t.inboxPage(true),secondRead=paging.requests.at(-1);
  paging.t.state.page=3;const third=paging.t.inboxPage(true),thirdRead=paging.requests.at(-1);
  assert.match(thirdRead.url,/offset=40/);thirdRead.reply({items:[message('Page three')],total:80});await third;
  secondRead.reply({items:[message('Page two')],total:80});await second;
  assert.equal(paging.t.state.page,3);assert.match(paging.node('#mail-table-body').innerHTML,/Page three/);
  const writes=paging.node('#mail-table-body').writes;
  const background=paging.t.inboxPage(false,true);paging.requests.at(-1).reply({items:[message('Page three')],total:80});await background;
  assert.equal(paging.node('#mail-table-body').writes,writes,'unchanged polling does not replace table rows');
  paging.document.hidden=true;const before=paging.requests.length;await paging.t.inboxPage(false,true);
  assert.equal(paging.requests.length,before,'hidden tabs skip mailbox polling');
  paging.document.hidden=false;
  paging.node('#mail-search').oninput({target:{value:'typed'}});
  assert.ok([...paging.timers.values()].some(timer=>timer.ms===180),'search uses a short debounce');
  const duringTyping=paging.requests.length;await paging.t.inboxPage(false,true);assert.equal(paging.requests.length,duringTyping);
  paging.node('#mail-search').onkeydown({key:'Enter'});
  assert.match(paging.requests.at(-1).url,/q=typed/);paging.requests.at(-1).reply({items:[],total:0});await tick();

  const switched=fixture();await loadInbox(switched);
  const leaving=switched.t.inboxPage(true),leavingRead=switched.requests.at(-1);
  switched.t.state.tab='security';await switched.t.renderPage();const pageMarkup=switched.node('#page').innerHTML;
  assert.equal(leavingRead.opt.signal.aborted,true);
  leavingRead.reply({items:[message('Wrong page')],total:1});await leaving;
  assert.equal(switched.node('#page').innerHTML,pageMarkup);
  // Security's independent retention read is irrelevant to this stale mail completion.

  const shared=fixture(),a=shared.t.api('/projects'),b=shared.t.api('/projects');
  assert.equal(a,b);assert.equal(shared.requests.length,1);
  shared.pending('/projects').reply([]);await Promise.all([a,b]);
  const retry=shared.t.api('/projects');shared.pending('/projects').reply({detail:'retryable'},503);
  await assert.rejects(retry,/retryable/);
  const retrySuccess=shared.t.api('/projects');shared.pending('/projects').reply([]);await retrySuccess;
  const readBeforeWrite=shared.t.api('/webhooks'),mutation=shared.t.api('/webhooks/1',{method:'PATCH',body:'{}'});
  shared.pending('/1').reply({});await mutation;
  const readAfterWrite=shared.t.api('/webhooks');
  assert.notEqual(readBeforeWrite,readAfterWrite,'writes fence shared read requests');
  shared.requests.filter(r=>!r.settled).forEach(r=>r.reply([]));await Promise.all([readBeforeWrite,readAfterWrite]);

  const session=fixture();session.context.expired=0;vm.runInContext('logout=()=>{expired++};',session.context);
  const expired=session.t.api('/api-keys');session.t.state.token='session-b';session.pending('/api-keys').reply({},401);
  await assert.rejects(expired,/登录已过期/);assert.equal(session.context.expired,0,'old 401 cannot log out a replacement session');
  const stale=session.t.api('/projects');session.t.state.token='session-c';session.pending('/projects').reply([{id:'private'}]);
  await assert.rejects(stale,{name:'AbortError'});
  const empty=fixture(),emptyFirst=empty.t.readProjects();empty.pending('/projects').reply([]);await emptyFirst;await empty.t.readProjects();
  assert.equal(empty.requests.length,1,'empty successful project lists also have a short cache');

  const names=fixture(),oldNames=names.t.ensureDomains(),oldNamesRead=names.requests.at(-1);
  names.t.invalidateAvailableDomains();const newNames=names.t.ensureDomains(),newNamesRead=names.requests.at(-1);
  assert.notEqual(newNamesRead,oldNamesRead,'domain changes invalidate both data and its pending request');
  newNamesRead.reply([{domain:'new.example.test'}]);await newNames;
  oldNamesRead.reply([{domain:'old.example.test'}]);await oldNames;
  assert.equal(names.t.state.domains[0].domain,'new.example.test');
  names.t.invalidateAvailableDomains();const reread=names.t.ensureDomains();
  assert.equal(names.requests.length,3,'clearing domain data also bypasses its completed short cache');
  names.requests.at(-1).reply([{domain:'latest.example.test'}]);await reread;

  const compose=fixture();compose.t.state.tab='send';await compose.t.sendPage();
  assert.equal(typeof compose.node('#send-form').onsubmit,'function','compose is interactive before domains or projects resolve');
  assert.equal(compose.requests.length,2);compose.node('#send-text').value='Draft remains';
  compose.node('#send-from').value='custom@example.test';compose.node('#send-from').oninput();
  compose.pending('/projects').reply([{id:'p1',name:'Project',enabled:true}]);await tick();
  assert.equal(compose.node('#send-project').disabled,false,'projects hydrate without waiting for domains');
  compose.pending('/domains').reply([{domain:'example.test'}]);await tick();
  assert.equal(compose.node('#send-from').value,'custom@example.test');assert.equal(compose.node('#send-text').value,'Draft remains');

  const autoSender=fixture();autoSender.t.state.tab='send';await autoSender.t.sendPage();
  autoSender.pending('/domains').reply([{domain:'example.test'}]);autoSender.pending('/projects').reply([]);await tick();
  assert.match(autoSender.node('#send-from').value,/@example\.test$/);

  const cachedForm=fixture();cachedForm.t.state.tab='send';await cachedForm.t.sendPage();
  const cachedSender=cachedForm.node('#send-from'),cachedProject=cachedForm.node('#send-project'),cachedChoices=cachedForm.node('#domain-senders');
  cachedForm.t.state.tab='security';
  for(const key of ['#send-from','#send-project','#domain-senders','#send-domain-summary'])cachedForm.nodes.delete(key);
  cachedForm.pending('/domains').reply([{domain:'cached.example.test'}]);cachedForm.pending('/projects').reply([{id:'p1',name:'Cached',enabled:true}]);await tick();
  assert.match(cachedSender.value,/@cached\.example\.test$/,'detached cached compose forms still finish auxiliary loading');
  assert.equal(cachedProject.disabled,false);assert.match(cachedChoices.innerHTML,/cached\.example\.test/);

  const latestKeys=fixture();latestKeys.t.state.tab='keys';
  vm.runInContext('globalThis.loadKeys=keysPage;',latestKeys.context);
  const priorKeys=latestKeys.context.loadKeys(true),priorKeysRead=latestKeys.requests.at(-1);
  const keyChange=latestKeys.t.api('/api-keys/1',{method:'PATCH',body:'{}'});
  latestKeys.pending('/1').reply({});await keyChange;
  const nextKeys=latestKeys.context.loadKeys(true),nextKeysRead=latestKeys.requests.at(-1);
  nextKeysRead.reply([{id:1,name:'Updated',created_at:1}]);await nextKeys;
  priorKeysRead.reply([{id:1,name:'Old version',created_at:1}]);await priorKeys;
  assert.match(latestKeys.node('#page').innerHTML,/Updated/);assert.doesNotMatch(latestKeys.node('#page').innerHTML,/Old version/);

  const key=fixture(),keyLoad=key.t.createKey();
  assert.match(key.node('#modal-root').innerHTML,/正在加载项目/);
  key.t.closeModal();key.pending('/projects').reply([]);await keyLoad;
  assert.equal(key.node('#modal-root').innerHTML,'','closed key dialogs stay closed after a slow response');
  const webhook=fixture(),hookLoad=webhook.t.showWebhookDeliveries(1,'https://fixture.test/hook');
  assert.equal(typeof webhook.node('#close-hook-delivery').onclick,'function','Webhook history opens immediately');
  webhook.t.closeModal();webhook.pending('/deliveries?limit=100').reply({items:[]});webhook.pending('/dead-letter?limit=100').reply({items:[]});await hookLoad;
  assert.equal(webhook.node('#modal-root').innerHTML,'','closed webhook history cannot reopen');

  const indexed=fixture(),claims=[{id:'b',domain:'x'},{id:'a',domain:'y'},{id:'a',domain:'x'}];
  indexed.t.state.controlClaims=claims;
  for(const domain of ['x','y',{domain:'x',claim_id:'a'},{domain:'z',claim_id:'a'}]){
    const name=typeof domain==='string'?domain:domain.domain;
    assert.equal(indexed.t.claimForDomain(domain),claims.find(c=>c.domain===name||Boolean(domain.claim_id&&c.id===domain.claim_id)));
  }
  indexed.t.state.controlClaims=[{id:'new',domain:'x'}];assert.equal(indexed.t.claimForDomain('x').id,'new');
  indexed.t.state.controlCredentials=[{id:'c',label:'old'}];assert.equal(indexed.t.controlCredential('c').label,'old');
  indexed.t.state.controlCredentials=[{id:'c',label:'updated'}];assert.equal(indexed.t.controlCredential('c').label,'updated');
  console.log('PASS: immediate independent loading, latest search/page wins, cancellation, stable polling, GET coalescing/retry/write fences, session isolation, draft retention, closeable loading dialogs and refreshed indexes');
})().catch(error=>{console.error(error);process.exitCode=1});
