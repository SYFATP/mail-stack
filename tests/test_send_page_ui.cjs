const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const html=fs.readFileSync(path.join(__dirname,'../frontend/index.html'),'utf8');
const source=html.match(/<script>([\s\S]*?)<\/script>/)[1];
const plain=value=>JSON.parse(JSON.stringify(value));
const settle=()=>new Promise(setImmediate);
function fixture(){
  const nodes=new Map(),requests=[],downloads=[],toasts=[];
  const fresh=()=>({innerHTML:'',textContent:'',value:'',open:false,disabled:false,files:[],dataset:{},isConnected:true,
    classList:{toggle(){}},focus(){},getClientRects(){return [{}]},append(child){this.child=child},setAttribute(name,value){this[name]=value}});
  const node=key=>{if(!nodes.has(key))nodes.set(key,fresh());return nodes.get(key)};
  let modal='';Object.defineProperty(node('#modal-root'),'innerHTML',{get:()=>modal,set:value=>{modal=value;nodes.set('#domain-dialog-bg',fresh())}});
  node('#send-form').reset=()=>{for(const key of ['send-html','send-reply-to','send-in-reply-to','send-references','send-project','send-text'])node('#'+key).value='';node('#send-attachments').files=[]};
  const rows=[{request_id:'send_fixture_detail',status:'submitted_to_mta',sender:'sender@example.test',recipients:['one@outside.test','two@outside.test'],transport:'smtp',accepted:['one@outside.test','two@outside.test'],rejected:{},attempts:1,created_at:1791258842,updated_at:1791258850},
    {request_id:'send_fixture_failed',status:'failed',sender:'<img src=x onerror=evil()>',recipients:['other@outside.test'],last_error:'fixture failure',accepted:[],rejected:{},updated_at:1791258851}];
  let gate=null,release=null,failure=null,status='submitted_to_mta';
  const context=vm.createContext({console,localStorage:{getItem:()=>null},crypto:{randomUUID:()=> '1234-5678-fixture'},
    setTimeout:fn=>{fn();return 1},clearTimeout(){},setInterval:()=>1,clearInterval(){},
    document:{body:{classList:{toggle(){}}},activeElement:null,createElement:()=>fresh(),querySelector:key=>key==='#domain-dialog-bg'&&!modal?null:node(key),querySelectorAll:selector=>{
      if(selector==='[data-send-detail]')return rows.map(row=>{const n=node(selector+row.request_id);n.dataset.sendDetail=row.request_id;return n});
      if(selector==='[data-replay-send]'){if(!rows[1])return [];const n=node('replay');n.dataset.replaySend=rows[1].request_id;return [n]}
      return [];
    }},
    fetch:async(url,options={})=>{
      requests.push({url,options});if(gate&&url.endsWith(gate.suffix))await gate.promise;
      if(failure&&url.endsWith(failure)){failure=null;return {ok:false,status:500,json:async()=>({detail:'fixture error'})}}
      let data={};
      if(url.endsWith('/projects'))data=[];
      else if(url.includes('/send?'))data={items:rows,total:24};
      else if(url.endsWith('/content'))data={...rows[0],content_available:true,subject:'Subject <img src=x onerror=evil()>',content:{text:'Body <script>evil()</script>',html:'<p>HTML body</p>'},attachments:[{filename:'fixture <attachment>.txt',content_type:'text/plain',size:100}],reply_to:'reply@example.test',references:['<thread@example.test>']};
      else if(url.endsWith('/send/queue'))data={request_id:'send_fixture_detail',status:'queued'};
      else if(url.endsWith('/replay'))data={status:'queued'};
      else if(url.includes('/send/'))data={...rows[0],status,delivery_reports:[]};
      return {ok:true,status:200,json:async()=>plain(data)};
    }});
  vm.runInContext(source+'\nglobalThis.test={state,sendPage,loadSendHistory,showSendDetail,closeModal,sendStatusLabel};',context);
  context.downloads=downloads;context.toasts=toasts;vm.runInContext('downloadFile=async(path,name)=>downloads.push({path,name});toast=(message,bad)=>toasts.push({message,bad});',context);
  const t=context.test;t.state.token='fixture';t.state.tab='send';t.state.domains=[{domain:'example.test'}];
  const form=()=>{for(const [key,value] of Object.entries({'send-from':'sender@example.test','send-to':'one@outside.test，two@outside.test','send-subject':'中文主题','send-text':'中文正文','send-html':'<p>HTML</p>','send-reply-to':'reply@example.test','send-in-reply-to':'<original@example.test>','send-references':'<thread@example.test>\n<original@example.test>','send-project':'prj_fixture'}))node('#'+key).value=value};
  return {node,t,requests,downloads,toasts,form,rows,pause(suffix){gate={suffix,promise:new Promise(resolve=>release=resolve)}},resume(){release();gate=null},fail(suffix){failure=suffix},setStatus(value){status=value}};
}
(async()=>{
  const f=fixture();await f.t.sendPage();
  const markup=f.node('#page').innerHTML;
  for(const id of ['send-advanced','send-api-example','send-history']){
    assert.match(markup,new RegExp('<details[^>]*id="'+id+'"[^>]*>'));
    assert.doesNotMatch(markup,new RegExp('<details[^>]*id="'+id+'"[^>]* open'));
  }
  assert.match(markup,/回复地址（Reply-To，可选）/);assert.match(markup,/回复的邮件 ID（In-Reply-To，可选）/);assert.match(markup,/会话关联 ID（References，可选）/);
  assert.equal(f.requests.filter(r=>r.url.includes('/send?')).length,0,'history loads only when expanded');
  f.node('#send-history').open=true;f.node('#send-history').ontoggle();await settle();
  assert.match(f.node('#send-history-body').innerHTML,/sender@example.test/);assert.match(f.node('#send-history-body').innerHTML,/two@outside.test/);
  assert.match(f.node('#send-history-body').innerHTML,/邮件服务器已接受/);assert.doesNotMatch(f.node('#send-history-body').innerHTML,/<img/);
  assert.match(f.node('#send-history-summary').textContent,/共 24 条/);
  await f.t.showSendDetail('send_fixture_detail');
  assert.match(f.node('#send-detail-content').innerHTML,/Body &lt;script&gt;/);assert.match(f.node('#send-detail-content').innerHTML,/fixture &lt;attachment&gt;/);
  assert.doesNotMatch(f.node('#send-detail-content').innerHTML,/<script>|<img/);
  assert.equal(f.node('#send-detail-html').child.sandbox,'');
  await f.node('#download-send-eml').onclick();assert.equal(f.downloads[0].path,'/send/send_fixture_detail/raw');
  f.t.closeModal();f.pause('/content');const pending=f.t.showSendDetail('send_fixture_detail');f.t.closeModal();f.resume();await pending;assert.equal(f.node('#modal-root').innerHTML,'','closed detail never reopens');
  f.form();f.node('#send-advanced').oninput();assert.match(f.node('#send-advanced-summary').textContent,/已填写 5 项/);
  f.pause('/send/queue');const send=f.node('#send-form').onsubmit({preventDefault(){}});await settle();
  const count=f.requests.filter(r=>r.options.method==='POST'&&r.url.endsWith('/send/queue')).length;
  await f.node('#send-form').onsubmit({preventDefault(){}});assert.equal(f.requests.filter(r=>r.options.method==='POST'&&r.url.endsWith('/send/queue')).length,count);
  const queued=f.requests.find(r=>r.options.method==='POST'&&r.url.endsWith('/send/queue'));
  const payload=JSON.parse(queued.options.body);assert.deepEqual(payload.recipients,['one@outside.test','two@outside.test']);assert.deepEqual(payload.references,['<thread@example.test>','<original@example.test>']);assert.equal(payload.reply_to,'reply@example.test');assert.equal(payload.html,'<p>HTML</p>');assert.equal(payload.project_id,'prj_fixture');
  f.resume();await send;assert.equal(f.node('#send-submit').disabled,false);assert.equal(f.node('#send-text').value,'');assert.match(f.node('#send-result').textContent,/发送通道：SMTP/);
  f.form();f.fail('/send/queue');await f.node('#send-form').onsubmit({preventDefault(){}});assert.equal(f.node('#send-text').value,'中文正文');assert.equal(f.node('#send-submit').disabled,false);assert.equal(f.node('#send-msg').textContent,'fixture error');
  f.fail('/send?limit=20');await f.t.loadSendHistory();assert.match(f.node('#send-history-body').innerHTML,/读取失败/);
  f.rows.length=0;await f.t.loadSendHistory();assert.match(f.node('#send-history-body').innerHTML,/暂无发件记录/);
  console.log('PASS: collapsed options/history/API, Chinese labels, address history, escaped MIME detail, sandboxed HTML, raw download, lazy loading, duplicate-submit guard, draft retention and thread payload');
})().catch(error=>{console.error(error);process.exitCode=1});
