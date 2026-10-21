const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../frontend/index.html'), 'utf8');
const source = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const A='prj_fixture_alpha', B='prj_fixture_bravo', C='prj_fixture_disabled';
function fixture() {
  const nodes=new Map(),requests=[],toasts=[];
  const node=key=>{
    if(!nodes.has(key))nodes.set(key,{innerHTML:'',textContent:'',value:'',checked:false,hidden:false,disabled:false,dataset:{},classList:{toggle(){}},focus(){},append(){}});
    return nodes.get(key);
  };
  let current={id:9,name:'Business <key>',key_type:'normal',global_access:false,scopes:['mail.read','mail.send','webhook.manage'],created_at:1,
    grants:[{project_id:A,scopes:['mail.read']},{project_id:C,scopes:['webhook.manage']}]};
  let fail=false,release=null,delay=null;
  const projects=[{id:A,name:'Alpha',enabled:true},{id:B,name:'Bravo',enabled:true},{id:C,name:'Disabled',enabled:false}];
  const context=vm.createContext({
    console,document:{body:{classList:{toggle(){}}},querySelector:node,querySelectorAll:selector=>{
      const match=selector.match(/^\[data-(edit-key|del-key)\]$/);if(!match)return [];
      const key=match[1]==='edit-key'?'editKey':'delKey';
      const element=node(selector);element.dataset[key]='9';return [element];
    },createElement:()=>({className:'',remove(){}})},
    localStorage:{getItem:()=>null},setTimeout:()=>1,clearTimeout(){},setInterval:()=>1,clearInterval(){},
    fetch:async(url,options={})=>{
      requests.push({url,options});let data;
      if(options.method==='PATCH'){
        if(delay)await delay;
        if(fail){fail=false;return {ok:false,status:400,json:async()=>({detail:'fixture edit rejected'})};}
        const body=JSON.parse(options.body);current={...current,...body,global_access:body.key_type==='admin'};
        data=current;
      }else if(url.endsWith('/projects'))data=projects;
      else if(url.endsWith('/api-keys/9'))data=current;
      else if(url.endsWith('/api-keys'))data=[current];
      else throw Error('Unexpected request '+url);
      return {ok:true,status:200,json:async()=>JSON.parse(JSON.stringify(data))};
    },
  });
  const owned=context;
  vm.runInContext(source+'\nglobalThis.test={editKey,keysPage,state};',owned);
  vm.runInContext('toast=(text,bad)=>{globalThis.toastResults.push([text,bad])}',owned);
  owned.toastResults=toasts;
  owned.test.state.token='fixture-session';
  return {node,requests,toasts,t:owned.test,failNext:()=>{fail=true},pause:()=>{delay=new Promise(resolve=>release=resolve)},resume:()=>{release();delay=null}};
}
(async()=>{
  const f=fixture();
  await f.t.keysPage(true);
  assert.match(f.node('#page').innerHTML,/data-edit-key="9">修改/);
  await f.node('[data-edit-key]').onclick();
  assert.match(f.node('#modal-root').innerHTML,/修改 API Key · ID 9/);
  assert.match(f.node('#modal-root').innerHTML,/Business &lt;key&gt;/);
  assert.match(f.node('#modal-root').innerHTML,/保存修改/);
  assert.equal(f.node('#key-grant-0').checked,true);
  assert.equal(f.node('#key-grant-0-mail-read').checked,true);
  assert.equal(f.node('#key-grant-0-mail-send').checked,false);
  assert.equal(f.node('#key-grant-1-mail-read').disabled,true);
  assert.equal(f.node('#key-grant-2').checked,true);
  assert.equal(f.node('#key-grant-2-webhook-manage').checked,true);
  f.node('#key-name').value='Renamed';
  f.node('#key-grant-0').checked=false;f.node('#key-grant-0').onchange();
  f.node('#key-grant-1').checked=true;f.node('#key-grant-1').onchange();
  f.node('#key-grant-1-mail-send').checked=false;
  f.failNext();await f.node('#key-form').onsubmit({preventDefault(){}});
  assert.equal(f.node('#key-error').textContent,'fixture edit rejected');
  assert.equal(f.node('#key-name').value,'Renamed');
  assert.match(f.node('#modal-root').innerHTML,/保存修改/);
  assert.equal(f.node('#save-key').disabled,false);
  f.pause();const submitting=f.node('#key-form').onsubmit({preventDefault(){}});
  const count=f.requests.length;
  await f.node('#key-form').onsubmit({preventDefault(){}});
  assert.equal(f.requests.length,count,'duplicate save must not send a second request');
  f.resume();await submitting;
  const patch=f.requests.filter(r=>r.options.method==='PATCH').at(-1);
  assert.equal(patch.url,'/api/v1/api-keys/9');
  const payload=JSON.parse(patch.options.body);
  assert.equal(payload.name,'Renamed');assert.equal(payload.key_type,'normal');
  assert.deepEqual(payload.grants,[{project_id:B,scopes:['mail.read','webhook.manage']},{project_id:C,scopes:['webhook.manage']}]);
  assert.equal(Object.hasOwn(payload,'key'),false);
  assert.equal(f.node('#modal-root').innerHTML,'');
  assert.match(f.node('#page').innerHTML,/Renamed/);
  assert.match(f.toasts.at(-1)[0],/原密钥继续有效/);

  await f.t.editKey(9);
  f.node('#key-type').value='admin';f.node('#key-type').onchange();
  assert.equal(f.node('#key-project-field').hidden,true);
  assert.equal(f.node('#key-global-note').hidden,false);
  await f.node('#key-form').onsubmit({preventDefault(){}});
  const adminBody=JSON.parse(f.requests.filter(r=>r.options.method==='PATCH').at(-1).options.body);
  assert.equal(adminBody.key_type,'admin');assert.equal(Object.hasOwn(adminBody,'grants'),false,'admin edits preserve existing grants');
  await f.t.editKey(9);
  f.node('#key-type').value='normal';f.node('#key-type').onchange();
  assert.equal(f.node('#key-project-field').hidden,false);
  assert.equal(f.node('#key-grant-1').checked,true);

  for(const scope of ['mail-read','mail-send','webhook-manage','domain-manage'])f.node('#key-scope-'+scope).checked=false;
  const before=f.requests.length;
  await f.node('#key-form').onsubmit({preventDefault(){}});
  assert.equal(f.requests.length,before);
  assert.match(f.node('#key-error').textContent,/至少选择一项 Key 权限/);
  f.node('#key-scope-mail-read').checked=true;
  for(const scope of ['mail-read','mail-send','webhook-manage','domain-manage'])f.node('#key-grant-1-'+scope).checked=false;
  await f.node('#key-form').onsubmit({preventDefault(){}});
  assert.equal(f.requests.length,before);
  assert.match(f.node('#key-error').textContent,/每个授权项目/);
  console.log('PASS: edit entry, per-project scope preservation, atomic PATCH, error retry, duplicate save, admin/global grants and validation');
})().catch(error=>{console.error(error);process.exitCode=1});
