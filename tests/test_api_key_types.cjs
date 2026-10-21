const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../frontend/index.html'), 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const nodes = new Map();
const node = key => {
  if (!nodes.has(key)) nodes.set(key, {innerHTML:'',textContent:'',value:'',hidden:false,disabled:false,dataset:{},classList:{toggle(){}},focus(){}});
  return nodes.get(key);
};
const requests = [];
const context = vm.createContext({
  document:{body:{classList:{toggle(){}}},querySelector:node,querySelectorAll:()=>[]},
  localStorage:{getItem:()=>null},console,setTimeout:()=>1,clearTimeout(){},setInterval:()=>1,clearInterval(){},
  fetch:async(url,options={})=>{
    requests.push({url,options});
    let data=[];
    if (url.endsWith('/projects')) data=[{id:'prj_fixture_project',name:'Fixture',enabled:true}];
    if (options.method==='POST') data={key:'ms_fixture_only',key_type:url.includes('key_type=admin')?'admin':'normal'};
    return {ok:true,status:200,json:async()=>data};
  },
});
vm.runInContext(source+'\nglobalThis.test={createKey,keysPage,state};',context);
(async()=>{
  const t=context.test;t.state.token='fixture-session';
  await t.createKey();
  assert.match(node('#modal-root').innerHTML,/<option value="normal" selected>普通<\/option>/);
  assert.match(node('#modal-root').innerHTML,/<option value="admin">管理员<\/option>/);
  node('#key-name').value='Regular';node('#key-type').value='normal';node('#key-project').value='prj_fixture_project';
  await node('#key-form').onsubmit({preventDefault(){}});
  const regular=requests.find(r=>r.options.method==='POST');
  assert.match(regular.url,/key_type=normal/);assert.match(regular.url,/project_id=prj_fixture_project/);
  assert.doesNotMatch(regular.url,/global_access=true/);
  await t.createKey();node('#key-name').value='modern admin';node('#key-type').value='admin';
  node('#key-type').onchange();assert.equal(node('#key-project-field').hidden,true);
  node('#key-project').value='prj_fixture_project';
  await node('#key-form').onsubmit({preventDefault(){}});
  const admin=requests.filter(r=>r.options.method==='POST')[1];
  assert.match(admin.url,/key_type=admin/);assert.doesNotMatch(admin.url,/project_id=/);
  assert.match(node('#modal-root').innerHTML,/管理员 API Key 已创建/);
  t.state.keys=[{id:1,name:'Normal',key_type:'normal',created_at:1},{id:2,name:'Admin',key_type:'admin',global_access:true,created_at:1}];
  await t.keysPage();
  assert.match(node('#page').innerHTML,/<span class="pill">普通<\/span>/);
  assert.match(node('#page').innerHTML,/<span class="pill">管理员<\/span>/);
  console.log('PASS: normal defaults, scoped normal creation, explicit global admin creation and type labels');
})().catch(error=>{console.error(error);process.exitCode=1});
