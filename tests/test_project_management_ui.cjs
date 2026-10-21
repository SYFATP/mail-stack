const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../frontend/index.html'),'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const A='prj_fixture_alpha',B='prj_fixture_bravo',C='prj_fixture_disabled';
const plain=value=>JSON.parse(JSON.stringify(value));
const settle=()=>new Promise(setImmediate);
function fixture(){
  const nodes=new Map(),requests=[],toasts=[];
  const fresh=()=>({innerHTML:'',textContent:'',value:'',checked:false,hidden:false,disabled:false,isConnected:true,dataset:{},classList:{toggle(){}},focus(){},getClientRects(){return [{}]}});
  const node=key=>{if(!nodes.has(key))nodes.set(key,fresh());return nodes.get(key)};
  let markup='';Object.defineProperty(node('#modal-root'),'innerHTML',{get:()=>markup,set:value=>{markup=value;nodes.set('#domain-dialog-bg',fresh())}});
  const projects=[{id:A,name:'Alpha <project>',enabled:true,created_at:1,domain_count:1,message_count:3,key_count:2,webhook_count:1},
    {id:B,name:'Bravo',enabled:true,created_at:1},{id:C,name:'Disabled',enabled:false,created_at:1}];
  const domains=[{domain:'fixture.example.test',project_id:A,users:['user'],enabled:true,dns_provider:'manual',receive_mode:'catch_all',max_subdomain_depth:2}];
  let failure=null,gate=null,release=null;
  const context=vm.createContext({console,localStorage:{getItem:()=>null},setTimeout:()=>1,clearTimeout(){},setInterval:()=>1,clearInterval(){},
    document:{body:{classList:{toggle(){}}},querySelector:node,activeElement:null,querySelectorAll:selector=>{
      const match=selector.match(/^\[data-(edit-project|copy-project)\]$/);if(!match)return [];
      return projects.map(p=>{const item=node(selector+':'+p.id);item.dataset[match[1]==='edit-project'?'editProject':'copyProject']=p.id;return item});
    }},
    fetch:async(url,options={})=>{
      requests.push({url,options});if(gate&&url.endsWith('/projects')&&!options.method)await gate;
      if(failure&&failure===url.split('?')[0]){failure=null;return {ok:false,status:409,json:async()=>({detail:'fixture conflict'})}}
      let data={},pathname=url.split('?')[0];
      if(pathname.endsWith('/projects')&&!options.method)data=projects;
      else if(pathname.endsWith('/projects')&&options.method==='POST'){
        data={id:'prj_fixture_created',name:new URL('http://fixture'+url).searchParams.get('name'),enabled:true,created_at:2};projects.push(data);
      }else if(pathname.includes('/projects/')&&options.method==='PATCH'){
        data=projects.find(p=>p.id===pathname.split('/').at(-1));Object.assign(data,JSON.parse(options.body));
      }else if(pathname.endsWith('/mail-domains')&&!options.method)data=domains;
      else if(pathname.includes('/mail-domains/')&&options.method==='PATCH'){
        data=domains[0];Object.assign(data,JSON.parse(options.body));if(typeof data.users==='string')data.users=data.users.split(',').map(v=>v.trim()).filter(Boolean);
      }else if(pathname.endsWith('/dns/cloudflare'))data={configured:false};
      return {ok:true,status:200,json:async()=>plain(data)};
    }});
  vm.runInContext(source+'\nglobalThis.test={state,projectsPage,projectForm,showDomainEditor,domainListData,closeModal};',context);
  context.toastResults=toasts;vm.runInContext('toast=(message,bad)=>toastResults.push({message,bad});',context);
  const t=context.test;t.state.token='fixture-session';t.state.tab='projects';t.state.mailDomains=plain(domains);
  const form=()=>{
    for(const [id,value] of Object.entries({'domain-name':'fixture.example.test','domain-users':'user','domain-selector':'default','domain-mx':'mx.example.test','domain-spf':'v=spf1 -all','domain-dmarc':'v=DMARC1; p=none','domain-depth':'2','domain-receive-mode':'catch_all','domain-dns-provider':'manual'}))node('#'+id).value=value;
    node('#domain-enabled').checked=true;node('#domain-receive-enabled').checked=true;
  };
  return {node,t,requests,toasts,projects,domains,form,fail:url=>failure=url,pause:()=>gate=new Promise(resolve=>release=resolve),resume:()=>{release();gate=null}};
}
(async()=>{
  const f=fixture();await f.t.projectsPage();
  assert.match(f.node('#page').innerHTML,/项目管理/);assert.match(f.node('#page').innerHTML,/Alpha &lt;project&gt;/);
  assert.match(f.node('#page').innerHTML,/>域名<\/th><th>邮件<\/th><th>Key/);
  assert.match(f.node('#page').innerHTML,/data-edit-project="prj_fixture_alpha"/);
  f.node('#new-project').onclick();f.node('#project-name').value=' New project & integration ';
  f.pause();const create=f.node('#project-form').onsubmit({preventDefault(){}});const count=f.requests.length;
  await f.node('#project-form').onsubmit({preventDefault(){}});assert.equal(f.requests.length,count);
  f.resume();await create;
  const request=f.requests.find(r=>r.options.method==='POST');assert.equal(new URL('http://fixture'+request.url).searchParams.get('name'),'New project & integration');
  assert.equal(f.node('#modal-root').innerHTML,'');assert.match(f.node('#page').innerHTML,/New project &amp; integration/);
  f.node('[data-edit-project]:'+A).onclick();assert.equal(f.node('#project-name').value,'Alpha <project>');
  assert.match(f.node('#modal-root').innerHTML,/id="project-id"[^>]*readonly/);
  f.node('#project-name').value='Renamed';f.node('#project-enabled').checked=false;f.fail('/api/v1/projects/'+A);
  await f.node('#project-form').onsubmit({preventDefault(){}});
  assert.equal(f.node('#project-error').textContent,'fixture conflict');assert.equal(f.node('#project-name').value,'Renamed');
  assert.equal(f.node('#save-project').disabled,false);
  await f.node('#project-form').onsubmit({preventDefault(){}});
  const edit=f.requests.filter(r=>r.options.method==='PATCH').at(-1);assert.equal(edit.url,'/api/v1/projects/'+A);
  assert.deepEqual(JSON.parse(edit.options.body),{name:'Renamed',enabled:false});
  assert.equal(f.projects[0].id,A);assert.match(f.node('#page').innerHTML,/已停用/);

  f.t.state.tab='domains';f.t.showDomainEditor('fixture.example.test');await settle();
  assert.equal(f.node('#domain-project').value,A);assert.equal(f.node('#domain-project').dataset.loaded,'true');
  assert.match(f.node('#domain-project').innerHTML,/Renamed（已停用）/);assert.doesNotMatch(f.node('#domain-project').innerHTML,new RegExp(C));
  f.form();f.node('#domain-project').value=B;await f.node('#domain-form').onsubmit({preventDefault(){}});
  assert.equal(JSON.parse(f.requests.filter(r=>r.options.method==='PATCH').at(-1).options.body).project_id,B);
  f.t.showDomainEditor('fixture.example.test');await settle();f.form();f.node('#domain-project').value='';
  await f.node('#domain-form').onsubmit({preventDefault(){}});
  assert.equal(JSON.parse(f.requests.filter(r=>r.options.method==='PATCH').at(-1).options.body).project_id,null);
  f.domains[0].project_id=A;f.t.state.mailDomains=plain(f.domains);
  f.fail('/api/v1/projects');f.t.showDomainEditor('fixture.example.test');await settle();f.form();
  assert.equal(f.node('#domain-project').disabled,true);assert.match(f.node('#domain-project-status').textContent,/现有归属保持不变/);
  await f.node('#domain-form').onsubmit({preventDefault(){}});
  assert.equal(Object.hasOwn(JSON.parse(f.requests.filter(r=>r.options.method==='PATCH').at(-1).options.body),'project_id'),false);
  assert.equal(f.domains[0].project_id,A);
  f.t.state.domainQuery=A;assert.equal(f.t.domainListData().total,1);
  f.t.state.domainQuery='Renamed';assert.equal(f.t.domainListData().total,1);

  const stale=fixture();stale.pause();const loading=stale.t.projectsPage();stale.t.state.tab='keys';stale.node('#page').innerHTML='Other page';
  stale.resume();await loading;assert.equal(stale.node('#page').innerHTML,'Other page');
  const closed=fixture();closed.t.state.tab='domains';closed.pause();closed.t.showDomainEditor('fixture.example.test');
  closed.t.closeModal();closed.resume();await settle();assert.equal(closed.node('#modal-root').innerHTML,'');
  assert.notEqual(closed.node('#domain-project').dataset.loaded,'true','closed dialog must reject late project data');
  console.log('PASS: project create/edit/status, names/counts, duplicate save, conflict retry, domain assignment/clear, disabled ownership preservation, failed loading and stale response guards');
})().catch(error=>{console.error(error);process.exitCode=1});
